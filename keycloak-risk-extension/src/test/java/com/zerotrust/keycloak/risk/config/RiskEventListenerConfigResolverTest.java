package com.zerotrust.keycloak.risk.config;

import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticatorConfigModel;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RiskEventListenerConfigResolverTest {

    private final RiskEventListenerConfigResolver resolver =
            new RiskEventListenerConfigResolver(new RiskAuthenticatorConfigResolver());

    @Test
    void defaultsToPortalClient() {
        RiskEventListenerConfig config = resolver.resolve(model(Map.of()));

        assertEquals(
                RiskEventListenerConfigResolver.DEFAULT_MONITORED_CLIENT_ID,
                config.monitoredClientId()
        );
    }

    @Test
    void resolvesExplicitMonitoredClient() {
        RiskEventListenerConfig config = resolver.resolve(model(Map.of(
                RiskEventListenerConfigResolver.MONITORED_CLIENT_ID,
                " another-spa "
        )));

        assertEquals("another-spa", config.monitoredClientId());
    }

    private static AuthenticatorConfigModel model(Map<String, String> values) {
        Map<String, String> completeValues = new HashMap<>();
        completeValues.put(
                RiskAuthenticatorConfigResolver.SERVICE_BASE_URL,
                "http://risk-scoring-service:8081"
        );
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
