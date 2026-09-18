package com.zerotrust.keycloak.risk.config;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RiskScoringClientConfigTest {

    @Test
    void createsEvaluationUriWithoutDuplicatingSlash() {
        RiskScoringClientConfig config = RiskScoringClientConfig.defaults(
                URI.create("http://localhost:8081/")
        );

        assertEquals(
                URI.create("http://localhost:8081/internal/v1/risk/evaluations"),
                config.evaluationUri()
        );
        assertEquals(
                URI.create("http://localhost:8081/internal/v1/trusted-devices"),
                config.trustedDevicesUri()
        );
        assertEquals(
                URI.create("http://localhost:8081/internal/v1/authentication-failures"),
                config.authenticationFailuresUri()
        );
        assertEquals(
                URI.create("http://localhost:8081/internal/v1/authentication-successes"),
                config.authenticationSuccessesUri()
        );
    }

    @Test
    void rejectsUnsupportedScheme() {
        assertThrows(
                IllegalArgumentException.class,
                () -> RiskScoringClientConfig.defaults(URI.create("file:///tmp/risk"))
        );
    }

    @Test
    void rejectsNonPositiveTimeout() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new RiskScoringClientConfig(
                        URI.create("http://localhost:8081"),
                        Duration.ZERO,
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(3),
                        64 * 1024
                )
        );
    }

    @Test
    void rejectsResponseSizeLimitWhenNotPositive() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new RiskScoringClientConfig(
                        URI.create("http://localhost:8081"),
                        Duration.ofMillis(500),
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(3),
                        0
                )
        );
    }

    @Test
    void rejectsCredentialsEmbeddedInServiceUrl() {
        assertThrows(
                IllegalArgumentException.class,
                () -> RiskScoringClientConfig.defaults(
                        URI.create("http://user:password@localhost:8081")
                )
        );
    }
}
