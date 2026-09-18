package com.zerotrust.keycloak.risk.config;

import java.util.Objects;

public record RiskEventListenerConfig(
        RiskAuthenticatorConfig riskConfig,
        String monitoredClientId
) {
    public RiskEventListenerConfig {
        Objects.requireNonNull(riskConfig, "riskConfig must not be null");
        if (monitoredClientId == null || monitoredClientId.isBlank()) {
            throw new IllegalArgumentException("monitoredClientId must not be blank");
        }
        monitoredClientId = monitoredClientId.trim();
    }
}
