package com.zerotrust.risk.domain;

import java.util.Objects;

public record DeviceRecognition(DeviceRecognitionStatus status, String fingerprintHash, Reason reason) {
    public enum Reason { MISSING_IDENTIFIER, NOT_REGISTERED, PENDING, TRUSTED, SECURITY_REVOKED,
        TRUST_EXPIRED, MFA_RESET, REAUTHENTICATION_REQUIRED }

    public DeviceRecognition(DeviceRecognitionStatus status, String fingerprintHash) {
        this(status, fingerprintHash, switch (status) {
            case MISSING -> Reason.MISSING_IDENTIFIER;
            case NEW -> Reason.NOT_REGISTERED;
            case PENDING -> Reason.PENDING;
            case TRUSTED -> Reason.TRUSTED;
            case REVOKED -> Reason.SECURITY_REVOKED;
            case REAUTHENTICATION_REQUIRED -> Reason.REAUTHENTICATION_REQUIRED;
        });
    }
    public DeviceRecognition {
        Objects.requireNonNull(status, "status must not be null");
        if (status != DeviceRecognitionStatus.MISSING && fingerprintHash == null) {
            throw new IllegalArgumentException("fingerprintHash is required for a present device");
        }
    }

    public static DeviceRecognition missing() {
        return new DeviceRecognition(DeviceRecognitionStatus.MISSING, null);
    }
}
