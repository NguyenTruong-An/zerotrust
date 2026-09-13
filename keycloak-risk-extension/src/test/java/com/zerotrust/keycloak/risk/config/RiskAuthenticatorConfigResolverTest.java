package com.zerotrust.keycloak.risk.config;

import com.zerotrust.keycloak.risk.policy.RiskFailureMode;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticatorConfigModel;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RiskAuthenticatorConfigResolverTest {

    private final RiskAuthenticatorConfigResolver resolver = new RiskAuthenticatorConfigResolver();

    @Test
    void resolvesRequiredUrlAndSafeDefaults() {
        AuthenticatorConfigModel model = model(Map.of(
                RiskAuthenticatorConfigResolver.SERVICE_BASE_URL,
                "http://risk-scoring-service:8081"
        ));

        RiskAuthenticatorConfig result = resolver.resolve(model);

        assertEquals(
                URI.create("http://risk-scoring-service:8081"),
                result.clientConfig().serviceBaseUri()
        );
        assertEquals(RiskFailureMode.DENY, result.failureMode());
        assertEquals(
                URI.create("http://keycloak:8080/realms/DoAn/protocol/openid-connect/token"),
                result.serviceTokenConfig().tokenEndpointUri()
        );
        assertEquals(
                ServiceTokenConfig.DEFAULT_CLIENT_ID,
                result.serviceTokenConfig().clientId()
        );
        assertEquals(
                RiskScoringClientConfig.DEFAULT_MAX_RESPONSE_BYTES,
                result.clientConfig().maxResponseBytes()
        );
    }

    @Test
    void resolvesExplicitStepUpFailureModeAndTimeouts() {
        AuthenticatorConfigModel model = model(Map.of(
                RiskAuthenticatorConfigResolver.SERVICE_BASE_URL, "http://localhost:8081",
                RiskAuthenticatorConfigResolver.FAILURE_MODE, "step_up_mfa",
                RiskAuthenticatorConfigResolver.CONNECT_TIMEOUT_MS, "750",
                RiskAuthenticatorConfigResolver.SOCKET_TIMEOUT_MS, "1250"
        ));

        RiskAuthenticatorConfig result = resolver.resolve(model);

        assertEquals(RiskFailureMode.STEP_UP_MFA, result.failureMode());
        assertEquals(750, result.clientConfig().connectTimeout().toMillis());
        assertEquals(1250, result.clientConfig().socketTimeout().toMillis());
    }

    @Test
    void rejectsMissingServiceUrl() {
        assertThrows(
                RiskAuthenticatorConfigurationException.class,
                () -> resolver.resolve(model(Map.of()))
        );
    }

    @Test
    void rejectsMissingServiceClientSecret() {
        AuthenticatorConfigModel model = new AuthenticatorConfigModel();
        model.setConfig(Map.of(
                RiskAuthenticatorConfigResolver.SERVICE_BASE_URL, "http://localhost:8081",
                RiskAuthenticatorConfigResolver.TOKEN_ENDPOINT_URL,
                "http://localhost:8180/realms/DoAn/protocol/openid-connect/token"
        ));

        assertThrows(
                RiskAuthenticatorConfigurationException.class,
                () -> resolver.resolve(model)
        );
    }

    @Test
    void rejectsInvalidIntegerSetting() {
        AuthenticatorConfigModel model = model(Map.of(
                RiskAuthenticatorConfigResolver.SERVICE_BASE_URL, "http://localhost:8081",
                RiskAuthenticatorConfigResolver.CONNECT_TIMEOUT_MS, "not-a-number"
        ));

        assertThrows(
                RiskAuthenticatorConfigurationException.class,
                () -> resolver.resolve(model)
        );
    }

    private static AuthenticatorConfigModel model(Map<String, String> values) {
        Map<String, String> completeValues = new HashMap<>();
        completeValues.put(
                RiskAuthenticatorConfigResolver.TOKEN_ENDPOINT_URL,
                "http://keycloak:8080/realms/DoAn/protocol/openid-connect/token"
        );
        completeValues.put(
                RiskAuthenticatorConfigResolver.SERVICE_CLIENT_SECRET,
                "test-client-secret"
        );
        completeValues.putAll(values);
        AuthenticatorConfigModel model = new AuthenticatorConfigModel();
        model.setConfig(completeValues);
        return model;
    }
}
