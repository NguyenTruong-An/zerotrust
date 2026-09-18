package com.zerotrust.keycloak.risk.config;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

public record RiskScoringClientConfig(
        URI serviceBaseUri,
        Duration connectionRequestTimeout,
        Duration connectTimeout,
        Duration socketTimeout,
        int maxResponseBytes
) {
    public static final Duration DEFAULT_CONNECTION_REQUEST_TIMEOUT = Duration.ofMillis(500);
    public static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(2);
    public static final Duration DEFAULT_SOCKET_TIMEOUT = Duration.ofSeconds(3);
    public static final int DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024;
    public static final int MAX_ALLOWED_RESPONSE_BYTES = 1024 * 1024;

    private static final String EVALUATION_PATH = "/internal/v1/risk/evaluations";
    private static final String TRUSTED_DEVICES_PATH = "/internal/v1/trusted-devices";
    private static final String AUTHENTICATION_FAILURES_PATH =
            "/internal/v1/authentication-failures";
    private static final String AUTHENTICATION_SUCCESSES_PATH =
            "/internal/v1/authentication-successes";

    public RiskScoringClientConfig {
        Objects.requireNonNull(serviceBaseUri, "serviceBaseUri must not be null");
        requirePositive(connectionRequestTimeout, "connectionRequestTimeout");
        requirePositive(connectTimeout, "connectTimeout");
        requirePositive(socketTimeout, "socketTimeout");
        if (maxResponseBytes <= 0 || maxResponseBytes > MAX_ALLOWED_RESPONSE_BYTES) {
            throw new IllegalArgumentException("maxResponseBytes must be between 1 and "
                    + MAX_ALLOWED_RESPONSE_BYTES);
        }

        String scheme = serviceBaseUri.getScheme();
        if (!("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
            throw new IllegalArgumentException("serviceBaseUri must use http or https");
        }
        if (serviceBaseUri.getAuthority() == null) {
            throw new IllegalArgumentException("serviceBaseUri must contain a host");
        }
        if (serviceBaseUri.getRawQuery() != null || serviceBaseUri.getRawFragment() != null) {
            throw new IllegalArgumentException("serviceBaseUri must not contain a query or fragment");
        }
        if (serviceBaseUri.getRawUserInfo() != null) {
            throw new IllegalArgumentException("serviceBaseUri must not contain credentials");
        }
    }

    public static RiskScoringClientConfig defaults(URI serviceBaseUri) {
        return new RiskScoringClientConfig(
                serviceBaseUri,
                DEFAULT_CONNECTION_REQUEST_TIMEOUT,
                DEFAULT_CONNECT_TIMEOUT,
                DEFAULT_SOCKET_TIMEOUT,
                DEFAULT_MAX_RESPONSE_BYTES
        );
    }

    public URI evaluationUri() {
        return endpointUri(EVALUATION_PATH);
    }

    public URI trustedDevicesUri() {
        return endpointUri(TRUSTED_DEVICES_PATH);
    }

    public URI authenticationFailuresUri() {
        return endpointUri(AUTHENTICATION_FAILURES_PATH);
    }

    public URI authenticationSuccessesUri() {
        return endpointUri(AUTHENTICATION_SUCCESSES_PATH);
    }

    private URI endpointUri(String path) {
        String base = serviceBaseUri.toString();
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        return URI.create(base + path);
    }

    private static void requirePositive(Duration duration, String fieldName) {
        Objects.requireNonNull(duration, fieldName + " must not be null");
        long milliseconds = duration.toMillis();
        if (milliseconds <= 0 || milliseconds > Integer.MAX_VALUE) {
            throw new IllegalArgumentException(fieldName + " must be between 1ms and "
                    + Integer.MAX_VALUE + "ms");
        }
    }

    public static int timeoutMillis(Duration duration) {
        return Math.toIntExact(duration.toMillis());
    }
}
