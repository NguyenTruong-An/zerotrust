package com.zerotrust.keycloak.risk.config;

import com.zerotrust.keycloak.risk.policy.RiskFailureMode;

import java.util.Objects;

public record RiskAuthenticatorConfig(
        RiskScoringClientConfig clientConfig,
        ServiceTokenConfig serviceTokenConfig,
        RiskFailureMode failureMode
) {
    public RiskAuthenticatorConfig {
        Objects.requireNonNull(clientConfig, "clientConfig must not be null");
        Objects.requireNonNull(serviceTokenConfig, "serviceTokenConfig must not be null");
        Objects.requireNonNull(failureMode, "failureMode must not be null");
    }
}
