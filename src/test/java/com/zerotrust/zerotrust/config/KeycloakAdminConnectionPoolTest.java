package com.zerotrust.zerotrust.config;

import com.sun.net.httpserver.HttpServer;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.core.Response;
import org.apache.http.conn.ConnectionPoolTimeoutException;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeycloakAdminConnectionPoolTest {
    @Test
    void boundsPoolWaitAndRecoversWhenOccupiedConnectionIsReleased() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        AtomicInteger probeRequests = new AtomicInteger();
        server.createContext("/realms/test-realm/protocol/openid-connect/token", exchange -> {
            byte[] token = """
                    {"access_token":"test-only-token","token_type":"bearer","expires_in":3600}
                    """.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, token.length);
            try (var body = exchange.getResponseBody()) {
                body.write(token);
            }
        });
        server.createContext("/probe", exchange -> {
            probeRequests.incrementAndGet();
            byte[] payload = new byte[64 * 1024];
            exchange.sendResponseHeaders(200, payload.length);
            try (var body = exchange.getResponseBody()) {
                body.write(payload);
            }
        });
        server.start();

        try {
            URI serverUri = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
            KeycloakAdminProperties properties = new KeycloakAdminProperties(
                    serverUri.toString(), "test-realm", "test-client", "test-only-secret",
                    Duration.ofSeconds(1), Duration.ofSeconds(5), Duration.ofMillis(200), 1, 10);
            try (Keycloak keycloak = new KeycloakAdminConfig().keycloakAdminClient(properties)) {
                ProbeResource probe = keycloak.proxy(ProbeResource.class, serverUri);
                // Leaving the first response unread occupies the only pooled connection.
                try (Response held = probe.get()) {
                    assertThat(held.getStatus()).isEqualTo(200);
                    Future<Integer> waiting = executor.submit(() -> {
                        try (Response response = probe.get()) {
                            return response.getStatus();
                        }
                    });

                    assertThatThrownBy(() -> waiting.get(2, TimeUnit.SECONDS))
                            .isInstanceOf(ExecutionException.class)
                            .hasCauseInstanceOf(ProcessingException.class)
                            .hasRootCauseInstanceOf(ConnectionPoolTimeoutException.class);
                    assertThat(probeRequests.get()).isEqualTo(1);
                }
                try (Response recovered = probe.get()) {
                    assertThat(recovered.getStatus()).isEqualTo(200);
                    assertThat(probeRequests.get()).isEqualTo(2);
                }
            }
        } finally {
            executor.shutdownNow();
            server.stop(0);
            assertThat(executor.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
        }
    }

    public interface ProbeResource {
        @GET
        @Path("/probe")
        Response get();
    }
}
