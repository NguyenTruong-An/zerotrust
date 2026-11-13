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
    private final com.zerotrust.risk.networkv2.NetworkRiskV2Shadow networkRiskV2;

    @PostMapping
    public RiskEvaluationResponse evaluate(@Valid @RequestBody RiskEvaluationRequest request) {
        var snapshot = deviceTrustLifecycle.snapshot(request.subjectId());
        var context = request.toDomain(java.time.Instant.now());
        RiskEvaluation evaluation = snapshot.resetPending()
                ? riskEvaluationService.denyForPendingReset()
                : riskEvaluationService.evaluate(context);
        // Observation is independent of the live B0 decision and response contract.
        networkRiskV2.observe(context, evaluation, snapshot.generation());
        return RiskEvaluationResponse.from(request, evaluation, snapshot.generation());
    }
}
