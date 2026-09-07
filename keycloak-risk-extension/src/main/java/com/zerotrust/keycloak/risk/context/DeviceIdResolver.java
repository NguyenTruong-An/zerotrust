package com.zerotrust.keycloak.risk.context;

import org.keycloak.authentication.AuthenticationFlowContext;

public interface DeviceIdResolver {

    String resolve(AuthenticationFlowContext context);
}
