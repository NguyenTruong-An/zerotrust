package com.zerotrust.keycloak.risk.dto;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.Instant;

public record AuthenticationSuccessRequest(
        String eventId,
        String subjectId,
        String clientId,
        @JsonFormat(shape = JsonFormat.Shape.STRING)
        Instant authenticatedAt,
        @com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL)
        java.util.UUID riskEvaluationId
) {
    public AuthenticationSuccessRequest(String eventId, String subjectId, String clientId, Instant authenticatedAt) {
        this(eventId, subjectId, clientId, authenticatedAt, null);
    }
}
