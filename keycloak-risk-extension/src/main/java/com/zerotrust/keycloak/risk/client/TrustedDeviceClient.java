package com.zerotrust.keycloak.risk.client;

import com.zerotrust.keycloak.risk.dto.TrustedDeviceRegistrationRequest;

public interface TrustedDeviceClient {

    void register(TrustedDeviceRegistrationRequest request);
}
