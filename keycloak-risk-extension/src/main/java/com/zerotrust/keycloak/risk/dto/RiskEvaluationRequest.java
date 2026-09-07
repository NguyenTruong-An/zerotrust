package com.zerotrust.keycloak.risk.dto;

public record RiskEvaluationRequest(
        String subjectId,
        String authenticationSessionId,
        String clientId,
        String ipAddress,
        String userAgent,
        String deviceId
) {
    public RiskEvaluationRequest {
        requireText(subjectId, "subjectId");
        requireText(authenticationSessionId, "authenticationSessionId");
        requireText(clientId, "clientId");
        requireText(ipAddress, "ipAddress");
    }

    private static void requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
    }
}
