package com.zerotrust.risk.dto.response;

import com.zerotrust.risk.dto.request.RiskEvaluationRequest;
import com.zerotrust.risk.domain.RiskDecision;
import com.zerotrust.risk.domain.RiskDataStatus;
import com.zerotrust.risk.domain.RiskEvaluation;
import com.zerotrust.risk.domain.RiskLevel;
import com.zerotrust.risk.domain.RiskReason;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
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
    public static RiskEvaluationResponse from(RiskEvaluationRequest request, RiskEvaluation evaluation) {
        return new RiskEvaluationResponse(
                evaluation.evaluationId(),
                request.subjectId(),
                request.authenticationSessionId(),
                evaluation.riskScore(),
                evaluation.riskLevel(),
                evaluation.decision(),
                evaluation.dataStatus(),
                evaluation.reasons(),
                evaluation.evaluatedAt()
        );
    }
}
