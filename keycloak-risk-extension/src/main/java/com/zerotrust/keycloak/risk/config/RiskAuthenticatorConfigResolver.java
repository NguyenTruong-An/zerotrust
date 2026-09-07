package com.zerotrust.keycloak.risk.config;

import com.zerotrust.keycloak.risk.policy.RiskFailureMode;
import org.keycloak.models.AuthenticatorConfigModel;

import java.net.URI;
import java.time.Duration;
import java.util.Map;

public final class RiskAuthenticatorConfigResolver {

    public static final String SERVICE_BASE_URL = "riskServiceBaseUrl";
    public static final String CONNECTION_REQUEST_TIMEOUT_MS = "connectionRequestTimeoutMs";
    public static final String CONNECT_TIMEOUT_MS = "connectTimeoutMs";
    public static final String SOCKET_TIMEOUT_MS = "socketTimeoutMs";
    public static final String MAX_RESPONSE_BYTES = "maxResponseBytes";
    public static final String FAILURE_MODE = "failureMode";

    public RiskAuthenticatorConfig resolve(AuthenticatorConfigModel model) {
        Map<String, String> values = model == null || model.getConfig() == null
                ? Map.of()
                : model.getConfig();

        String serviceBaseUrl = requireText(values.get(SERVICE_BASE_URL), SERVICE_BASE_URL);
        URI serviceBaseUri;
        try {
            serviceBaseUri = URI.create(serviceBaseUrl);
        } catch (IllegalArgumentException exception) {
            throw new RiskAuthenticatorConfigurationException(
                    SERVICE_BASE_URL + " is not a valid URI",
                    exception
            );
        }

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
            return new RiskAuthenticatorConfig(clientConfig, failureMode(values));
        } catch (IllegalArgumentException exception) {
            throw new RiskAuthenticatorConfigurationException(
                    "Risk authenticator configuration is invalid",
                    exception
            );
        }
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
