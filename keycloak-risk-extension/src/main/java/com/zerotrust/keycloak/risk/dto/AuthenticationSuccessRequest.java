package com.zerotrust.keycloak.risk.dto;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.Instant;

public record AuthenticationSuccessRequest(
        String eventId,
        String subjectId,
        String clientId,
        @JsonFormat(shape = JsonFormat.Shape.STRING)
        Instant authenticatedAt
) {
}
