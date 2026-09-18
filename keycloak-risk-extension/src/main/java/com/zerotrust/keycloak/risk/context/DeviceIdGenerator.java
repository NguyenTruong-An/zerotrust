package com.zerotrust.keycloak.risk.context;

@FunctionalInterface
public interface DeviceIdGenerator {

    String generate();
}
