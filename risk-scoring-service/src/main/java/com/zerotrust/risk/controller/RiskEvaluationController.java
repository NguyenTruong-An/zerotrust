package com.zerotrust.risk.controller;

import com.zerotrust.risk.dto.request.RiskEvaluationRequest;
import com.zerotrust.risk.dto.response.RiskEvaluationResponse;
import com.zerotrust.risk.domain.RiskEvaluation;
import com.zerotrust.risk.service.RiskEvaluationService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/v1/risk/evaluations")
public class RiskEvaluationController {

    private final RiskEvaluationService riskEvaluationService;

    public RiskEvaluationController(RiskEvaluationService riskEvaluationService) {
        this.riskEvaluationService = riskEvaluationService;
    }

    @PostMapping
    public RiskEvaluationResponse evaluate(@Valid @RequestBody RiskEvaluationRequest request) {
        RiskEvaluation evaluation = riskEvaluationService.evaluate(request.toDomain(java.time.Instant.now()));
        return RiskEvaluationResponse.from(request, evaluation);
    }
}
