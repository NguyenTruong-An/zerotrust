package com.zerotrust.risk.service;

import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.RiskDataStatus;
import com.zerotrust.risk.domain.RiskEvaluation;
import com.zerotrust.risk.domain.RiskFeatureExtraction;
import com.zerotrust.risk.domain.RiskReason;
import com.zerotrust.risk.trace.RiskScoreTrace;
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
    private final RiskScoreTrace trace;

    public RiskEvaluation evaluate(LoginContext context) {
        long started = System.nanoTime();
        var priority = priorityRuleEvaluator.firstViolation(context);
        if (priority.isPresent()) {
            return finish(riskScoringService.denyForPriorityRule(priority.orElseThrow()), null, started);
        }
        RiskFeatureExtraction extraction = featureExtractor.extract(context);
        return finish(evaluateFeatures(extraction), extraction, started);
    }

    public RiskEvaluation denyForPendingReset() {
        long started = System.nanoTime();
        return finish(riskScoringService.denyForPriorityRule(RiskReason.MFA_RESET_IN_PROGRESS), null, started);
    }

    private RiskEvaluation finish(RiskEvaluation result, RiskFeatureExtraction extraction, long started) {
        trace.record(result, extraction, System.nanoTime() - started);
        return result;
    }

    private RiskEvaluation evaluateFeatures(RiskFeatureExtraction extraction) {
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
