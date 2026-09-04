package com.zerotrust.risk.service;

import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.RiskDataStatus;
import com.zerotrust.risk.domain.RiskEvaluation;
import com.zerotrust.risk.domain.RiskFeatureExtraction;
import com.zerotrust.risk.feature.RiskFeatureExtractor;
import com.zerotrust.risk.rule.PrioritySecurityRuleEvaluator;
import org.springframework.stereotype.Service;

@Service
public class RiskEvaluationService {

    private final PrioritySecurityRuleEvaluator priorityRuleEvaluator;
    private final RiskFeatureExtractor featureExtractor;
    private final RiskScoringService riskScoringService;

    public RiskEvaluationService(
            PrioritySecurityRuleEvaluator priorityRuleEvaluator,
            RiskFeatureExtractor featureExtractor,
            RiskScoringService riskScoringService
    ) {
        this.priorityRuleEvaluator = priorityRuleEvaluator;
        this.featureExtractor = featureExtractor;
        this.riskScoringService = riskScoringService;
    }

    public RiskEvaluation evaluate(LoginContext context) {
        return priorityRuleEvaluator.firstViolation(context)
                .map(riskScoringService::denyForPriorityRule)
                .orElseGet(() -> evaluateFeatures(context));
    }

    private RiskEvaluation evaluateFeatures(LoginContext context) {
        RiskFeatureExtraction extraction = featureExtractor.extract(context);
        if (extraction.dataStatus() != RiskDataStatus.COMPLETE) {
            return riskScoringService.stepUpForIncompleteData(extraction.reasons());
        }
        return riskScoringService.evaluate(extraction.factors());
    }
}
