package com.zerotrust.keycloak.risk.config;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ServiceTokenConfigTest {

    @Test
    void neverIncludesClientSecretInStringRepresentation() {
        ServiceTokenConfig config = config("very-sensitive-secret");

        assertFalse(config.toString().contains("very-sensitive-secret"));
    }

    @Test
    void rejectsCredentialsEmbeddedInTokenEndpointUrl() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new ServiceTokenConfig(
                        URI.create("https://user:secret@keycloak/realms/DoAn/token"),
                        "zerotrust-risk-caller",
                        "client-secret",
                        Duration.ofSeconds(30)
                )
        );
    }

    @Test
    void rejectsNegativeRefreshSkew() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new ServiceTokenConfig(
                        URI.create("https://keycloak/realms/DoAn/token"),
                        "zerotrust-risk-caller",
                        "client-secret",
                        Duration.ofMillis(-1)
                )
        );
    }

    private static ServiceTokenConfig config(String clientSecret) {
        return new ServiceTokenConfig(
                URI.create("https://keycloak/realms/DoAn/protocol/openid-connect/token"),
                "zerotrust-risk-caller",
                clientSecret,
                Duration.ofSeconds(30)
        );
    }
}
