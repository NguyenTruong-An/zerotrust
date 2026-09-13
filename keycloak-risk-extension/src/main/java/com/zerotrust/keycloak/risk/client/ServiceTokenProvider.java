package com.zerotrust.keycloak.risk.client;

public interface ServiceTokenProvider {

    String accessToken();

    void invalidate(String rejectedToken);
}
