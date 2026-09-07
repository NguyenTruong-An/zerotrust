package com.zerotrust.keycloak.risk.dto;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

public record RiskEvaluationResponse(
        UUID evaluationId,
        String subjectId,
        String authenticationSessionId,
        BigDecimal riskScore,
        RiskLevel riskLevel,
        RiskDecision decision,
        RiskDataStatus dataStatus,
        List<RiskReason> reasons,
        Instant evaluatedAt
) {
    public RiskEvaluationResponse {
        Objects.requireNonNull(evaluationId, "evaluationId must not be null");
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        Objects.requireNonNull(authenticationSessionId, "authenticationSessionId must not be null");
        Objects.requireNonNull(riskLevel, "riskLevel must not be null");
        Objects.requireNonNull(decision, "decision must not be null");
        Objects.requireNonNull(dataStatus, "dataStatus must not be null");
        reasons = List.copyOf(Objects.requireNonNull(reasons, "reasons must not be null"));
        Objects.requireNonNull(evaluatedAt, "evaluatedAt must not be null");
    }
}
