package com.zerotrust.zerotrust.risk;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

class RiskDeviceAdminClientHttpTest {
    @Test
    void readTimeoutAlsoBoundsWaitingForTokenResponseBody() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        CountDownLatch releaseBody = new CountDownLatch(1);
        CountDownLatch responseBodyStarted = new CountDownLatch(1);
        AtomicInteger riskRequests = new AtomicInteger();
        server.createContext("/token", exchange -> {
            try {
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, 100);
                exchange.getResponseBody().write('{');
                exchange.getResponseBody().flush();
                responseBodyStarted.countDown();
                releaseBody.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
            } finally {
                exchange.close();
            }
        });
        server.createContext("/internal/v1/subjects/", exchange -> {
            riskRequests.incrementAndGet();
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        server.start();

        try {
            URI baseUri = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
            RiskAdminProperties properties = new RiskAdminProperties();
            properties.setBaseUrl(baseUri);
            properties.setTokenUri(baseUri.resolve("/token"));
            properties.setClientSecret("test-only-secret");
            properties.setAllowHttp(true);
            properties.setConnectTimeout(Duration.ofSeconds(1));
            properties.setReadTimeout(Duration.ofMillis(200));
            RiskDeviceAdminClient client = new RiskDeviceAdminClient(properties, new ObjectMapper());

            assertTimeoutPreemptively(Duration.ofSeconds(3), () ->
                    assertThatThrownBy(() -> client.revoke(UUID.randomUUID(), UUID.randomUUID(), "test-admin"))
                            .isInstanceOf(WebException.class)
                            .extracting(failure -> ((WebException) failure).getErrorCode())
                            .isEqualTo(ErrorCode.RISK_DEVICE_REVOCATION_FAILED));
            assertThat(responseBodyStarted.getCount()).isZero();
            assertThat(riskRequests.get()).isZero();
        } finally {
            releaseBody.countDown();
            server.stop(0);
        }
    }
}
