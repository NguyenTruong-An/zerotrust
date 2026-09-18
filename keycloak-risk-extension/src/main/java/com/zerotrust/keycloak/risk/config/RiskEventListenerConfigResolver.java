package com.zerotrust.keycloak.risk.config;

import org.keycloak.models.AuthenticatorConfigModel;

import java.util.Map;

public final class RiskEventListenerConfigResolver {

    public static final String MONITORED_CLIENT_ID = "monitoredEventClientId";
    public static final String DEFAULT_MONITORED_CLIENT_ID = "zerotrust-spa";

    private final RiskAuthenticatorConfigResolver authenticatorConfigResolver;

    public RiskEventListenerConfigResolver(
            RiskAuthenticatorConfigResolver authenticatorConfigResolver
    ) {
        this.authenticatorConfigResolver = authenticatorConfigResolver;
    }

    public RiskEventListenerConfig resolve(AuthenticatorConfigModel model) {
        Map<String, String> values = model == null || model.getConfig() == null
                ? Map.of()
                : model.getConfig();
        String configuredClient = values.get(MONITORED_CLIENT_ID);
        String monitoredClient = configuredClient == null || configuredClient.isBlank()
                ? DEFAULT_MONITORED_CLIENT_ID
                : configuredClient.trim();
        return new RiskEventListenerConfig(
                authenticatorConfigResolver.resolve(model),
                monitoredClient
        );
    }
}
