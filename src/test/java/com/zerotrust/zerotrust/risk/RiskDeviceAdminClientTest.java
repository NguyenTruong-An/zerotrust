package com.zerotrust.zerotrust.risk;

import com.zerotrust.zerotrust.exception.WebException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.net.URI;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class RiskDeviceAdminClientTest {
    private final RiskAdminProperties properties = properties();
    private final RestClient.Builder builder = RestClient.builder();
    private final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
    private final RiskDeviceAdminClient client = new RiskDeviceAdminClient(properties, builder.build());
    private final UUID subject = UUID.randomUUID();
    private final UUID operation = UUID.randomUUID();

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

    private void token(String value) {
        server.expect(requestTo("https://id.example/token")).andExpect(method(HttpMethod.POST))
                .andExpect(content().string(containsString("client_id=zerotrust-portal-risk-admin")))
                .andExpect(content().string(containsString("grant_type=client_credentials")))
                .andRespond(withSuccess("{\"access_token\":\"" + value + "\",\"token_type\":\"Bearer\",\"expires_in\":300}", MediaType.APPLICATION_JSON));
    }

    private String endpoint() { return "https://risk.example/internal/v1/subjects/" + subject + "/trusted-devices/revocations"; }
    private static RiskAdminProperties properties() {
        var result = new RiskAdminProperties();
        result.setBaseUrl(URI.create("https://risk.example"));
        result.setTokenUri(URI.create("https://id.example/token"));
        result.setClientSecret("test-secret");
        return result;
    }
}
