package com.zerotrust.risk.domain;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record RiskEvaluation(
        UUID evaluationId,
        BigDecimal riskScore,
        RiskLevel riskLevel,
        RiskDecision decision,
        RiskDataStatus dataStatus,
        List<RiskReason> reasons,
        Instant evaluatedAt
) {
    public RiskEvaluation {
        reasons = List.copyOf(reasons);
    }
}
