package com.zerotrust.keycloak.risk.client;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.zerotrust.keycloak.risk.config.RiskScoringClientConfig;
import com.zerotrust.keycloak.risk.dto.RiskDecision;
import com.zerotrust.keycloak.risk.dto.RiskEvaluationRequest;
import com.zerotrust.keycloak.risk.dto.RiskEvaluationResponse;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HttpRiskScoringClientTest {

    private static final String EVALUATION_PATH = "/internal/v1/risk/evaluations";

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
    void postsLoginContextAndReturnsDecision() {
        AtomicReference<String> method = new AtomicReference<>();
        AtomicReference<String> body = new AtomicReference<>();
        server.createContext(EVALUATION_PATH, exchange -> {
            method.set(exchange.getRequestMethod());
            body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            respond(exchange, 200, """
                    {
                      "evaluationId": "0ea3026d-2f0a-4ab8-a45e-8183e47f52e5",
                      "subjectId": "user-1",
                      "authenticationSessionId": "session-1",
                      "riskScore": null,
                      "riskLevel": "MEDIUM",
                      "decision": "STEP_UP_MFA",
                      "dataStatus": "INCOMPLETE",
                      "reasons": ["NEW_DEVICE", "NETWORK_INTELLIGENCE_UNAVAILABLE"],
                      "evaluatedAt": "2026-09-04T08:00:00Z"
                    }
                    """);
        });

        RiskEvaluationRequest request = request();
        RiskEvaluationResponse response = client().evaluate(request);

        assertEquals("POST", method.get());
        assertEquals(RiskDecision.STEP_UP_MFA, response.decision());
        assertEquals("user-1", response.subjectId());

        @SuppressWarnings("unchecked")
        Map<String, Object> requestJson = JsonSerialization.valueFromString(body.get(), Map.class);
        assertEquals("user-1", requestJson.get("subjectId"));
        assertEquals("203.0.113.10", requestJson.get("ipAddress"));
        assertEquals("device-123", requestJson.get("deviceId"));
    }

    @Test
    void rejectsHttpErrorWithoutTrustingItsBody() {
        server.createContext(EVALUATION_PATH, exchange -> respond(exchange, 503, """
                {"error":"service unavailable"}
                """));

        RiskScoringClientException exception = assertThrows(
                RiskScoringClientException.class,
                () -> client().evaluate(request())
        );

        assertEquals(RiskScoringClientException.FailureType.HTTP_ERROR, exception.failureType());
        assertEquals(503, exception.statusCode());
    }

    @Test
    void rejectsResponseBelongingToAnotherAuthenticationSession() {
        server.createContext(EVALUATION_PATH, exchange -> respond(exchange, 200, """
                {
                  "evaluationId": "0ea3026d-2f0a-4ab8-a45e-8183e47f52e5",
                  "subjectId": "user-1",
                  "authenticationSessionId": "another-session",
                  "riskScore": 10,
                  "riskLevel": "LOW",
                  "decision": "ALLOW",
                  "dataStatus": "COMPLETE",
                  "reasons": [],
                  "evaluatedAt": "2026-09-04T08:00:00Z"
                }
                """));

        RiskScoringClientException exception = assertThrows(
                RiskScoringClientException.class,
                () -> client().evaluate(request())
        );

        assertEquals(RiskScoringClientException.FailureType.INVALID_RESPONSE, exception.failureType());
    }

    @Test
    void rejectsNonJsonSuccessResponse() {
        server.createContext(EVALUATION_PATH, exchange -> respond(
                exchange,
                200,
                "text/html; charset=UTF-8",
                "not-json"
        ));

        RiskScoringClientException exception = assertThrows(
                RiskScoringClientException.class,
                () -> client().evaluate(request())
        );

        assertEquals(RiskScoringClientException.FailureType.INVALID_RESPONSE, exception.failureType());
    }

    @Test
    void rejectsResponseLargerThanConfiguredLimit() {
        server.createContext(EVALUATION_PATH, exchange -> respond(
                exchange,
                200,
                "application/json",
                "x".repeat(256)
        ));
        RiskScoringClientConfig config = new RiskScoringClientConfig(
                serviceUri(),
                Duration.ofMillis(500),
                Duration.ofSeconds(2),
                Duration.ofSeconds(3),
                128
        );

        RiskScoringClientException exception = assertThrows(
                RiskScoringClientException.class,
                () -> client(config).evaluate(request())
        );

        assertEquals(RiskScoringClientException.FailureType.INVALID_RESPONSE, exception.failureType());
    }

    @Test
    void classifiesSlowResponseAsTimeout() {
        server.createContext(EVALUATION_PATH, exchange -> {
            try {
                Thread.sleep(300);
                respond(exchange, 200, "{}");
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                exchange.close();
            }
        });
        RiskScoringClientConfig config = new RiskScoringClientConfig(
                serviceUri(),
                Duration.ofMillis(500),
                Duration.ofSeconds(2),
                Duration.ofMillis(50),
                64 * 1024
        );

        RiskScoringClientException exception = assertThrows(
                RiskScoringClientException.class,
                () -> client(config).evaluate(request())
        );

        assertEquals(RiskScoringClientException.FailureType.TIMEOUT, exception.failureType());
    }

    @Test
    void classifiesConnectionRefusalAsConnectionFailure() throws IOException {
        int unusedPort;
        try (ServerSocket socket = new ServerSocket(
                0,
                1,
                InetAddress.getLoopbackAddress()
        )) {
            unusedPort = socket.getLocalPort();
        }
        RiskScoringClientConfig config = RiskScoringClientConfig.defaults(
                URI.create("http://127.0.0.1:" + unusedPort)
        );

        RiskScoringClientException exception = assertThrows(
                RiskScoringClientException.class,
                () -> client(config).evaluate(request())
        );

        assertEquals(
                RiskScoringClientException.FailureType.CONNECTION_FAILURE,
                exception.failureType()
        );
    }

    @Test
    void rejectsMalformedJsonResponse() {
        server.createContext(EVALUATION_PATH, exchange -> respond(
                exchange,
                200,
                "{not-valid-json}"
        ));

        RiskScoringClientException exception = assertThrows(
                RiskScoringClientException.class,
                () -> client().evaluate(request())
        );

        assertEquals(RiskScoringClientException.FailureType.INVALID_RESPONSE, exception.failureType());
    }

    private HttpRiskScoringClient client() {
        return client(RiskScoringClientConfig.defaults(serviceUri()));
    }

    private HttpRiskScoringClient client(RiskScoringClientConfig config) {
        return new HttpRiskScoringClient(httpClient, config);
    }

    private URI serviceUri() {
        return URI.create("http://" + server.getAddress().getHostString()
                + ":" + server.getAddress().getPort());
    }

    private static RiskEvaluationRequest request() {
        return new RiskEvaluationRequest(
                "user-1",
                "session-1",
                "zerotrust-spa",
                "203.0.113.10",
                "Mozilla/5.0",
                "device-123"
        );
    }

    private static void respond(HttpExchange exchange, int statusCode, String responseBody)
            throws IOException {
        respond(exchange, statusCode, "application/json; charset=UTF-8", responseBody);
    }

    private static void respond(
            HttpExchange exchange,
            int statusCode,
            String contentType,
            String responseBody
    ) throws IOException {
        byte[] responseBytes = responseBody.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        exchange.getResponseBody().write(responseBytes);
        exchange.close();
    }
}
