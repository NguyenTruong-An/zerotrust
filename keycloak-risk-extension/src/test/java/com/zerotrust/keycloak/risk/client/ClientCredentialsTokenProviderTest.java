package com.zerotrust.keycloak.risk.client;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.zerotrust.keycloak.risk.config.RiskScoringClientConfig;
import com.zerotrust.keycloak.risk.config.ServiceTokenConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientCredentialsTokenProviderTest {

    private static final String TOKEN_PATH = "/realms/DoAn/protocol/openid-connect/token";
    private static final Instant START = Instant.parse("2026-09-09T00:00:00Z");

    private HttpServer server;
    private CloseableHttpClient httpClient;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.start();
        httpClient = HttpClients.custom()
                .disableAutomaticRetries()
                .disableRedirectHandling()
                .build();
    }

    @AfterEach
    void stopServer() throws IOException {
        server.stop(0);
        httpClient.close();
    }

    @Test
    void usesBasicClientAuthenticationAndCachesTokenUntilRefreshWindow() {
        AtomicInteger calls = new AtomicInteger();
        AtomicReference<String> method = new AtomicReference<>();
        AtomicReference<String> authorization = new AtomicReference<>();
        AtomicReference<String> contentType = new AtomicReference<>();
        AtomicReference<String> body = new AtomicReference<>();
        server.createContext(TOKEN_PATH, exchange -> {
            int call = calls.incrementAndGet();
            method.set(exchange.getRequestMethod());
            authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            contentType.set(exchange.getRequestHeaders().getFirst("Content-Type"));
            body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            respond(exchange, 200, """
                    {
                      "access_token": "token-%d",
                      "expires_in": 60,
                      "token_type": "Bearer"
                    }
                    """.formatted(call));
        });
        MutableClock clock = new MutableClock(START);
        ClientCredentialsTokenProvider provider = provider(clock, new ServiceTokenCache());

        assertEquals("token-1", provider.accessToken());
        clock.advance(Duration.ofSeconds(29));
        assertEquals("token-1", provider.accessToken());
        clock.advance(Duration.ofSeconds(2));
        assertEquals("token-2", provider.accessToken());

        assertEquals(2, calls.get());
        assertEquals("POST", method.get());
        assertEquals("grant_type=client_credentials", body.get());
        assertEquals(
                "Basic " + Base64.getEncoder().encodeToString(
                        "zerotrust-risk-caller:test-client-secret"
                                .getBytes(StandardCharsets.UTF_8)
                ),
                authorization.get()
        );
        assertTrue(contentType.get().startsWith("application/x-www-form-urlencoded"));
    }

    @Test
    void invalidatingRejectedTokenForcesOneNewTokenRequest() {
        AtomicInteger calls = new AtomicInteger();
        server.createContext(TOKEN_PATH, exchange -> {
            int call = calls.incrementAndGet();
            respond(exchange, 200, """
                    {
                      "access_token": "token-%d",
                      "expires_in": 300,
                      "token_type": "bearer"
                    }
                    """.formatted(call));
        });
        ClientCredentialsTokenProvider provider = provider(
                new MutableClock(START),
                new ServiceTokenCache()
        );

        String first = provider.accessToken();
        provider.invalidate("different-token");
        assertEquals(first, provider.accessToken());
        provider.invalidate(first);
        assertEquals("token-2", provider.accessToken());
        assertEquals(2, calls.get());
    }

    @Test
    void rejectsTokenEndpointErrorWithoutIncludingSecretOrResponseBody() {
        server.createContext(TOKEN_PATH, exchange -> respond(
                exchange,
                401,
                "{\"error_description\":\"test-client-secret leaked\"}"
        ));

        RiskScoringClientException exception = assertThrows(
                RiskScoringClientException.class,
                () -> provider(new MutableClock(START), new ServiceTokenCache()).accessToken()
        );

        assertEquals(RiskScoringClientException.FailureType.HTTP_ERROR, exception.failureType());
        assertEquals(401, exception.statusCode());
        assertFalse(exception.getMessage().contains("test-client-secret"));
        assertFalse(exception.getMessage().contains("error_description"));
    }

    @Test
    void rejectsMalformedSuccessResponse() {
        server.createContext(TOKEN_PATH, exchange -> respond(exchange, 200, """
                {
                  "access_token": "token-without-expiry",
                  "token_type": "Bearer"
                }
                """));

        RiskScoringClientException exception = assertThrows(
                RiskScoringClientException.class,
                () -> provider(new MutableClock(START), new ServiceTokenCache()).accessToken()
        );

        assertEquals(
                RiskScoringClientException.FailureType.INVALID_RESPONSE,
                exception.failureType()
        );
    }

    private ClientCredentialsTokenProvider provider(Clock clock, ServiceTokenCache cache) {
        ServiceTokenConfig tokenConfig = new ServiceTokenConfig(
                tokenUri(),
                "zerotrust-risk-caller",
                "test-client-secret",
                Duration.ofSeconds(30)
        );
        RiskScoringClientConfig networkConfig = RiskScoringClientConfig.defaults(serviceUri());
        return new ClientCredentialsTokenProvider(
                httpClient,
                tokenConfig,
                networkConfig,
                cache,
                clock
        );
    }

    private URI tokenUri() {
        return serviceUri().resolve(TOKEN_PATH);
    }

    private URI serviceUri() {
        return URI.create("http://" + server.getAddress().getHostString()
                + ":" + server.getAddress().getPort());
    }

    private static void respond(HttpExchange exchange, int statusCode, String responseBody)
            throws IOException {
        byte[] bytes = responseBody.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private static final class MutableClock extends Clock {
        private final AtomicReference<Instant> instant;

        private MutableClock(Instant instant) {
            this.instant = new AtomicReference<>(instant);
        }

        private void advance(Duration duration) {
            instant.updateAndGet(current -> current.plus(duration));
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant.get();
        }
    }
}
