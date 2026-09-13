package com.zerotrust.risk.domain;

import java.util.Objects;

public record DeviceRecognition(DeviceRecognitionStatus status, String fingerprintHash) {
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
