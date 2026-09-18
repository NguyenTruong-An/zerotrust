package com.zerotrust.keycloak.risk.dto;

import java.util.Objects;

public record TrustedDeviceRegistrationRequest(
        String subjectId,
        String deviceId
) {
    public TrustedDeviceRegistrationRequest {
        subjectId = requireText(subjectId, "subjectId");
        deviceId = requireText(deviceId, "deviceId");
    }

    private static String requireText(String value, String fieldName) {
        Objects.requireNonNull(value, fieldName + " must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }
}
