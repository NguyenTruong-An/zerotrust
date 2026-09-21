package com.zerotrust.risk.service;

import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.RiskDataStatus;
import com.zerotrust.risk.domain.RiskEvaluation;
import com.zerotrust.risk.domain.RiskFeatureExtraction;
import com.zerotrust.risk.feature.RiskFeatureExtractor;
import com.zerotrust.risk.rule.PrioritySecurityRuleEvaluator;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RiskEvaluationService {

    private final PrioritySecurityRuleEvaluator priorityRuleEvaluator;
    private final RiskFeatureExtractor featureExtractor;
    private final RiskScoringService riskScoringService;

    public RiskEvaluation evaluate(LoginContext context) {
        return priorityRuleEvaluator.firstViolation(context)
                .map(riskScoringService::denyForPriorityRule)
                .orElseGet(() -> evaluateFeatures(context));
    }

    private RiskEvaluation evaluateFeatures(LoginContext context) {
        RiskFeatureExtraction extraction = featureExtractor.extract(context);
        if (extraction.priorityViolation().isPresent()) {
            return riskScoringService.denyForPriorityRule(
                    extraction.priorityViolation().orElseThrow()
            );
        }
        if (extraction.dataStatus() != RiskDataStatus.COMPLETE) {
            return riskScoringService.stepUpForIncompleteData(extraction.reasons());
        }
        if (extraction.mandatoryStepUpReason().isPresent()) {
            return riskScoringService.evaluateWithRequiredStepUp(
                    extraction.factors(),
                    extraction.reasons()
            );
        }
        return riskScoringService.evaluate(extraction.factors());
    }
}
