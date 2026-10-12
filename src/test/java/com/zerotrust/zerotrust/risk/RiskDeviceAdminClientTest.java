package com.zerotrust.zerotrust.risk;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withNoContent;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class RiskDeviceAdminClientTest {
    private static final int MAX_TOKEN_RESPONSE_BYTES = 64 * 1024;
    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");
    private final RiskAdminProperties properties = properties();
    private final RestClient.Builder builder = RestClient.builder();
    private final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
    private final Clock clock = mock(Clock.class);
    private final RiskDeviceAdminClient client = new RiskDeviceAdminClient(
            properties, builder.build(), new ObjectMapper(), clock);
    private final UUID subject = UUID.randomUUID();
    private final UUID operation = UUID.randomUUID();

    @BeforeEach
    void setClock() {
        when(clock.instant()).thenReturn(NOW);
    }

    @Test
    void usesDedicatedCredentialsAndCachesTokenAcrossRevokeAndCompletion() {
        token("token-1");
        server.expect(requestTo(endpoint())).andExpect(method(HttpMethod.POST))
                .andExpect(header("Authorization", "Bearer token-1"))
                .andExpect(content().json("{\"operationId\":\"" + operation + "\",\"requestedBy\":\"admin-1\"}"))
                .andRespond(withNoContent());
        server.expect(requestTo(endpoint() + "/completion")).andExpect(header("Authorization", "Bearer token-1"))
                .andRespond(withNoContent());
        client.revoke(subject, operation, "admin-1");
        client.complete(subject, operation, "admin-1");
        server.verify();
    }

    @Test
    void refreshesRejectedTokenOnceWithoutChangingOperationId() {
        token("old-token");
        server.expect(requestTo(endpoint())).andRespond(withStatus(HttpStatus.UNAUTHORIZED));
        token("new-token");
        server.expect(requestTo(endpoint())).andExpect(header("Authorization", "Bearer new-token"))
                .andExpect(content().string(containsString(operation.toString())))
                .andRespond(withNoContent());
        client.revoke(subject, operation, "admin-1");
        server.verify();
    }

    @Test
    void unavailableRiskServiceFailsWithoutExposingRemoteBody() {
        token("secret-token");
        server.expect(requestTo(endpoint())).andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE).body("private remote details"));
        assertThatThrownBy(() -> client.revoke(subject, operation, "admin-1"))
                .isInstanceOf(WebException.class).hasMessageNotContaining("private").hasMessageNotContaining("secret-token");
        server.verify();
    }

    @Test
    void rejectsNon204ResponseAndInsecureOrReusedCredentials() {
        properties.setClientId("zerotrust-provisioner");
        assertThatThrownBy(() -> client.revoke(subject, operation, "admin-1")).isInstanceOf(WebException.class);
        properties.setClientId("zerotrust-portal-risk-admin");
        properties.setBaseUrl(URI.create("http://risk.example"));
        assertThatThrownBy(() -> client.revoke(subject, operation, "admin-1")).isInstanceOf(WebException.class);
        properties.setBaseUrl(URI.create("https://risk.example"));
        token("token-1");
        server.expect(requestTo(endpoint())).andRespond(withSuccess());
        assertThatThrownBy(() -> client.revoke(subject, operation, "admin-1")).isInstanceOf(WebException.class);
        server.verify();
    }

    @Test
    void rejectsOversizedTokenResponseEvenWhenContentLengthUnderstatesItsSize() {
        String json = "{\"access_token\":\"" + "x".repeat(MAX_TOKEN_RESPONSE_BYTES)
                + "\",\"token_type\":\"Bearer\",\"expires_in\":300}";
        TrackedInputStream body = new TrackedInputStream(json);
        server.expect(requestTo("https://id.example/token")).andRespond(request -> {
            var response = new MockClientHttpResponse(body, HttpStatus.OK);
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
            response.getHeaders().setContentLength(2);
            return response;
        });

        assertRevocationFailure();

        assertThat(body.bytesRead).isLessThanOrEqualTo(MAX_TOKEN_RESPONSE_BYTES + 1);
        assertThat(body.closed).isTrue();
        server.verify();
    }

    @ParameterizedTest
    @ValueSource(ints = {403, 503})
    void ignoresRemoteErrorBodyAndClosesResponseWithoutRetry(int status) {
        token("test-only-token");
        TrackedInputStream body = new TrackedInputStream("private remote details".repeat(5000));
        server.expect(requestTo(endpoint())).andRespond(request ->
                new MockClientHttpResponse(body, HttpStatus.valueOf(status)));

        assertRevocationFailure();

        assertThat(body.bytesRead).isZero();
        assertThat(body.closed).isTrue();
        server.verify();
    }

    @Test
    void ignoresTokenEndpointErrorBodyAndClosesResponse() {
        TrackedInputStream body = new TrackedInputStream("private token endpoint details".repeat(5000));
        server.expect(requestTo("https://id.example/token")).andRespond(request ->
                new MockClientHttpResponse(body, HttpStatus.UNAUTHORIZED));

        assertRevocationFailure();

        assertThat(body.bytesRead).isZero();
        assertThat(body.closed).isTrue();
        server.verify();
    }

    @ParameterizedTest
    @ValueSource(strings = {"\"300\"", "300.5", "9223372036854775808", "0", "-1", "null"})
    void rejectsInvalidTokenLifetime(String expiresIn) {
        server.expect(requestTo("https://id.example/token")).andRespond(withSuccess(
                "{\"access_token\":\"test-only-token\",\"token_type\":\"Bearer\",\"expires_in\":"
                        + expiresIn + "}", MediaType.APPLICATION_JSON));

        assertRevocationFailure();

        server.verify();
    }

    @Test
    void rejectsTokenResponseWithTrailingJson() {
        server.expect(requestTo("https://id.example/token")).andRespond(withSuccess(
                tokenJson("test-only-token", 300) + " {}", MediaType.APPLICATION_JSON));

        assertRevocationFailure();

        server.verify();
    }

    @Test
    void accountsForTokenRequestLatencyWhenRefreshing() {
        server.expect(requestTo("https://id.example/token")).andRespond(request -> {
            when(clock.instant()).thenReturn(NOW.plusSeconds(20));
            return withSuccess(tokenJson("first-token", 300), MediaType.APPLICATION_JSON)
                    .createResponse(request);
        });
        server.expect(requestTo(endpoint())).andRespond(withNoContent());
        server.expect(requestTo(endpoint() + "/completion"))
                .andExpect(header("Authorization", "Bearer first-token")).andRespond(withNoContent());
        token("refreshed-token");
        server.expect(requestTo(endpoint() + "/completion"))
                .andExpect(header("Authorization", "Bearer refreshed-token")).andRespond(withNoContent());

        client.revoke(subject, operation, "admin-1");
        when(clock.instant()).thenReturn(NOW.plusSeconds(269));
        client.complete(subject, operation, "admin-1");
        when(clock.instant()).thenReturn(NOW.plusSeconds(270));
        client.complete(subject, operation, "admin-1");

        server.verify();
    }

    @Test
    void rejectsTokenThatExpiresDuringFetch() {
        server.expect(requestTo("https://id.example/token")).andRespond(request -> {
            when(clock.instant()).thenReturn(NOW.plusSeconds(1));
            return withSuccess(tokenJson("test-only-token", 1), MediaType.APPLICATION_JSON)
                    .createResponse(request);
        });

        assertRevocationFailure();

        server.verify();
    }

    @Test
    void doesNotCacheTokenWithinRefreshSkew() {
        server.expect(requestTo("https://id.example/token")).andRespond(withSuccess(
                tokenJson("short-lived-token", 30), MediaType.APPLICATION_JSON));
        server.expect(requestTo(endpoint())).andExpect(header("Authorization", "Bearer short-lived-token"))
                .andRespond(withNoContent());
        token("refreshed-token");
        server.expect(requestTo(endpoint() + "/completion"))
                .andExpect(header("Authorization", "Bearer refreshed-token")).andRespond(withNoContent());

        client.revoke(subject, operation, "admin-1");
        client.complete(subject, operation, "admin-1");

        server.verify();
    }

    @Test
    void failsAfterSecondUnauthorizedResponseWithoutReadingItsBody() {
        token("first-token");
        TrackedInputStream firstBody = new TrackedInputStream("private first rejection");
        server.expect(requestTo(endpoint())).andRespond(request ->
                new MockClientHttpResponse(firstBody, HttpStatus.UNAUTHORIZED));
        token("second-token");
        TrackedInputStream secondBody = new TrackedInputStream("private second rejection");
        server.expect(requestTo(endpoint())).andRespond(request ->
                new MockClientHttpResponse(secondBody, HttpStatus.UNAUTHORIZED));

        assertRevocationFailure();

        assertThat(firstBody.bytesRead).isZero();
        assertThat(secondBody.bytesRead).isZero();
        assertThat(firstBody.closed).isTrue();
        assertThat(secondBody.closed).isTrue();
        server.verify();
    }

    @Test
    void discardsTokenRejectedOnLastAttemptBeforeTheNextOperation() {
        token("first-token");
        server.expect(requestTo(endpoint())).andRespond(withStatus(HttpStatus.UNAUTHORIZED));
        token("second-token");
        server.expect(requestTo(endpoint())).andRespond(withStatus(HttpStatus.UNAUTHORIZED));
        token("fresh-token");
        server.expect(requestTo(endpoint())).andExpect(header("Authorization", "Bearer fresh-token"))
                .andRespond(withNoContent());

        assertRevocationFailure();
        client.revoke(subject, operation, "admin-1");

        server.verify();
    }

    private void assertRevocationFailure() {
        assertThatThrownBy(() -> client.revoke(subject, operation, "admin-1"))
                .isInstanceOf(WebException.class)
                .hasMessageNotContaining("private")
                .hasMessageNotContaining("test-only-token")
                .extracting(failure -> ((WebException) failure).getErrorCode())
                .isEqualTo(ErrorCode.RISK_DEVICE_REVOCATION_FAILED);
    }

    private void token(String value) {
        server.expect(requestTo("https://id.example/token")).andExpect(method(HttpMethod.POST))
                .andExpect(content().string(containsString("client_id=zerotrust-portal-risk-admin")))
                .andExpect(content().string(containsString("grant_type=client_credentials")))
                .andRespond(withSuccess(tokenJson(value, 300), MediaType.APPLICATION_JSON));
    }

    private static String tokenJson(String value, long expiresIn) {
        return "{\"access_token\":\"" + value + "\",\"token_type\":\"Bearer\",\"expires_in\":" + expiresIn + "}";
    }

    private String endpoint() {
        return "https://risk.example/internal/v1/subjects/" + subject + "/trusted-devices/revocations";
    }
    private static RiskAdminProperties properties() {
        var result = new RiskAdminProperties();
        result.setBaseUrl(URI.create("https://risk.example"));
        result.setTokenUri(URI.create("https://id.example/token"));
        result.setClientSecret("test-secret");
        return result;
    }

    private static final class TrackedInputStream extends InputStream {
        private final ByteArrayInputStream delegate;
        private int bytesRead;
        private boolean closed;

        private TrackedInputStream(String value) {
            delegate = new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public int read() {
            int value = delegate.read();
            if (value != -1) {
                bytesRead++;
            }
            return value;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) {
            int count = delegate.read(buffer, offset, length);
            if (count > 0) {
                bytesRead += count;
            }
            return count;
        }

        @Override
        public void close() {
            closed = true;
        }
    }
}
