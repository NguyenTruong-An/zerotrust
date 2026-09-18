package com.zerotrust.keycloak.risk.context;

import org.keycloak.authentication.AuthenticationFlowContext;

public interface DeviceCookieWriter {

    void issue(AuthenticationFlowContext context, String deviceId);

    void expire(AuthenticationFlowContext context);
}
