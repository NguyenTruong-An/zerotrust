package com.zerotrust.risk.securitystate;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public final class SecurityStateRejected extends RuntimeException {
    public SecurityStateRejected() { super("Security context is unavailable or revoked"); }
}
