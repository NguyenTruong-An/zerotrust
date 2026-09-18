package com.zerotrust.keycloak.risk.client;

import com.zerotrust.keycloak.risk.config.RiskAuthenticatorConfig;

@FunctionalInterface
public interface TrustedDeviceClientFactory {

    TrustedDeviceClient create(RiskAuthenticatorConfig config);
}
