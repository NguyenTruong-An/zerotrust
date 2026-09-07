package com.zerotrust.keycloak.risk.config;

public final class RiskAuthenticatorConfigurationException extends RuntimeException {

    public RiskAuthenticatorConfigurationException(String message) {
        super(message);
    }

    public RiskAuthenticatorConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
