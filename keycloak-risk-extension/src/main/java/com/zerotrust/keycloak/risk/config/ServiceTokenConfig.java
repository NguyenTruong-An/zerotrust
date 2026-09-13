package com.zerotrust.keycloak.risk.config;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

public record ServiceTokenConfig(
        URI tokenEndpointUri,
        String clientId,
        String clientSecret,
        Duration refreshSkew
) {
    public static final String DEFAULT_CLIENT_ID = "zerotrust-risk-caller";
    public static final Duration DEFAULT_REFRESH_SKEW = Duration.ofSeconds(30);

    public ServiceTokenConfig {
        Objects.requireNonNull(tokenEndpointUri, "tokenEndpointUri must not be null");
        clientId = requireText(clientId, "clientId");
        clientSecret = requireText(clientSecret, "clientSecret");
        Objects.requireNonNull(refreshSkew, "refreshSkew must not be null");

        String scheme = tokenEndpointUri.getScheme();
        if (!("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
            throw new IllegalArgumentException("tokenEndpointUri must use http or https");
        }
        if (tokenEndpointUri.getAuthority() == null) {
            throw new IllegalArgumentException("tokenEndpointUri must contain a host");
        }
        if (tokenEndpointUri.getRawQuery() != null
                || tokenEndpointUri.getRawFragment() != null) {
            throw new IllegalArgumentException(
                    "tokenEndpointUri must not contain a query or fragment"
            );
        }
        if (tokenEndpointUri.getRawUserInfo() != null) {
            throw new IllegalArgumentException("tokenEndpointUri must not contain credentials");
        }
        if (refreshSkew.isNegative()) {
            throw new IllegalArgumentException("refreshSkew must not be negative");
        }
    }

    @Override
    public String toString() {
        return "ServiceTokenConfig[tokenEndpointUri=" + tokenEndpointUri
                + ", clientId=" + clientId
                + ", clientSecret=***"
                + ", refreshSkew=" + refreshSkew + "]";
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value.trim();
    }
}
