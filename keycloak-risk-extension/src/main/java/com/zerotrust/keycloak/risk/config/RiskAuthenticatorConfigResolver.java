package com.zerotrust.keycloak.risk.config;

import com.zerotrust.keycloak.risk.policy.RiskFailureMode;
import org.keycloak.models.AuthenticatorConfigModel;

import java.net.URI;
import java.time.Duration;
import java.util.Map;

public final class RiskAuthenticatorConfigResolver {

    public static final String SERVICE_BASE_URL = "riskServiceBaseUrl";
    public static final String TOKEN_ENDPOINT_URL = "tokenEndpointUrl";
    public static final String SERVICE_CLIENT_ID = "serviceClientId";
    public static final String SERVICE_CLIENT_SECRET = "serviceClientSecret";
    public static final String TOKEN_REFRESH_SKEW_MS = "tokenRefreshSkewMs";
    public static final String CONNECTION_REQUEST_TIMEOUT_MS = "connectionRequestTimeoutMs";
    public static final String CONNECT_TIMEOUT_MS = "connectTimeoutMs";
    public static final String SOCKET_TIMEOUT_MS = "socketTimeoutMs";
    public static final String MAX_RESPONSE_BYTES = "maxResponseBytes";
    public static final String FAILURE_MODE = "failureMode";

    public RiskAuthenticatorConfig resolve(AuthenticatorConfigModel model) {
        Map<String, String> values = model == null || model.getConfig() == null
                ? Map.of()
                : model.getConfig();

        URI serviceBaseUri = uri(values, SERVICE_BASE_URL);

        try {
            RiskScoringClientConfig clientConfig = new RiskScoringClientConfig(
                    serviceBaseUri,
                    duration(values, CONNECTION_REQUEST_TIMEOUT_MS,
                            RiskScoringClientConfig.DEFAULT_CONNECTION_REQUEST_TIMEOUT),
                    duration(values, CONNECT_TIMEOUT_MS,
                            RiskScoringClientConfig.DEFAULT_CONNECT_TIMEOUT),
                    duration(values, SOCKET_TIMEOUT_MS,
                            RiskScoringClientConfig.DEFAULT_SOCKET_TIMEOUT),
                    integer(values, MAX_RESPONSE_BYTES,
                            RiskScoringClientConfig.DEFAULT_MAX_RESPONSE_BYTES)
            );
            ServiceTokenConfig serviceTokenConfig = new ServiceTokenConfig(
                    uri(values, TOKEN_ENDPOINT_URL),
                    text(values, SERVICE_CLIENT_ID, ServiceTokenConfig.DEFAULT_CLIENT_ID),
                    requireText(values.get(SERVICE_CLIENT_SECRET), SERVICE_CLIENT_SECRET),
                    nonNegativeDuration(
                            values,
                            TOKEN_REFRESH_SKEW_MS,
                            ServiceTokenConfig.DEFAULT_REFRESH_SKEW
                    )
            );
            return new RiskAuthenticatorConfig(
                    clientConfig,
                    serviceTokenConfig,
                    failureMode(values)
            );
        } catch (IllegalArgumentException exception) {
            throw new RiskAuthenticatorConfigurationException(
                    "Risk authenticator configuration is invalid",
                    exception
            );
        }
    }

    private static URI uri(Map<String, String> values, String key) {
        String value = requireText(values.get(key), key);
        try {
            return URI.create(value);
        } catch (IllegalArgumentException exception) {
            throw new RiskAuthenticatorConfigurationException(
                    key + " is not a valid URI",
                    exception
            );
        }
    }

    private static String text(Map<String, String> values, String key, String defaultValue) {
        String value = values.get(key);
        return value == null || value.isBlank() ? defaultValue : value.trim();
    }

    private static Duration duration(
            Map<String, String> values,
            String key,
            Duration defaultValue
    ) {
        String value = values.get(key);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        return Duration.ofMillis(parsePositiveInteger(value, key));
    }

    private static int integer(Map<String, String> values, String key, int defaultValue) {
        String value = values.get(key);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        return parsePositiveInteger(value, key);
    }

    private static Duration nonNegativeDuration(
            Map<String, String> values,
            String key,
            Duration defaultValue
    ) {
        String value = values.get(key);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        try {
            int parsed = Integer.parseInt(value);
            if (parsed < 0) {
                throw new NumberFormatException("negative");
            }
            return Duration.ofMillis(parsed);
        } catch (NumberFormatException exception) {
            throw new RiskAuthenticatorConfigurationException(
                    key + " must be a non-negative integer",
                    exception
            );
        }
    }

    private static int parsePositiveInteger(String value, String key) {
        try {
            int parsed = Integer.parseInt(value);
            if (parsed <= 0) {
                throw new NumberFormatException("not positive");
            }
            return parsed;
        } catch (NumberFormatException exception) {
            throw new RiskAuthenticatorConfigurationException(
                    key + " must be a positive integer",
                    exception
            );
        }
    }

    private static RiskFailureMode failureMode(Map<String, String> values) {
        String value = values.getOrDefault(FAILURE_MODE, RiskFailureMode.DENY.name());
        try {
            return RiskFailureMode.valueOf(value.trim().toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            throw new RiskAuthenticatorConfigurationException(
                    FAILURE_MODE + " must be DENY or STEP_UP_MFA",
                    exception
            );
        }
    }

    private static String requireText(String value, String key) {
        if (value == null || value.isBlank()) {
            throw new RiskAuthenticatorConfigurationException(key + " is required");
        }
        return value.trim();
    }
}
