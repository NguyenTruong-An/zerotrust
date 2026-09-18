package com.zerotrust.keycloak.risk.client;

import com.zerotrust.keycloak.risk.dto.AuthenticationFailureRequest;
import com.zerotrust.keycloak.risk.dto.AuthenticationSuccessRequest;

public interface AuthenticationEventClient {

    void recordFailure(AuthenticationFailureRequest request);

    void recordSuccess(AuthenticationSuccessRequest request);
}
