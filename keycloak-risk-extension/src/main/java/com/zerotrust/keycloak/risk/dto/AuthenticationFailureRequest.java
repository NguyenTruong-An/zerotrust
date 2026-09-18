package com.zerotrust.keycloak.risk.dto;

public record AuthenticationFailureRequest(
        String eventId,
        String subjectId,
        String sourceIp
) {
}
