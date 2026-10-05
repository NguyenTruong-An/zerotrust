package com.zerotrust.risk.controller;

import com.zerotrust.risk.dto.request.RiskEvaluationRequest;
import com.zerotrust.risk.dto.response.RiskEvaluationResponse;
import com.zerotrust.risk.domain.RiskEvaluation;
import com.zerotrust.risk.service.RiskEvaluationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/v1/risk/evaluations")
@RequiredArgsConstructor
public class RiskEvaluationController {

    private final RiskEvaluationService riskEvaluationService;
    private final com.zerotrust.risk.service.DeviceTrustLifecycle deviceTrustLifecycle;

    @PostMapping
    public RiskEvaluationResponse evaluate(@Valid @RequestBody RiskEvaluationRequest request) {
        var snapshot = deviceTrustLifecycle.snapshot(request.subjectId());
        RiskEvaluation evaluation = snapshot.resetPending()
                ? new RiskEvaluation(java.util.UUID.randomUUID(), null,
                com.zerotrust.risk.domain.RiskLevel.HIGH, com.zerotrust.risk.domain.RiskDecision.DENY,
                com.zerotrust.risk.domain.RiskDataStatus.NOT_EVALUATED,
                java.util.List.of(com.zerotrust.risk.domain.RiskReason.MFA_RESET_IN_PROGRESS), java.time.Instant.now())
                : riskEvaluationService.evaluate(request.toDomain(java.time.Instant.now()));
        return RiskEvaluationResponse.from(request, evaluation, snapshot.generation());
    }
}
