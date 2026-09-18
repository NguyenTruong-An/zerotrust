package com.zerotrust.risk.exception;

public final class DeviceTrustRejectedException extends IllegalStateException {

    public DeviceTrustRejectedException() {
        super("revoked device cannot be trusted");
    }
}
