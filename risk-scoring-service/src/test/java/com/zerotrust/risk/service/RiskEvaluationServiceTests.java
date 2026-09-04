package com.zerotrust.risk.service;

import com.zerotrust.risk.config.RiskPolicyProperties;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.RiskDataStatus;
import com.zerotrust.risk.domain.RiskDecision;
import com.zerotrust.risk.domain.RiskEvaluation;
import com.zerotrust.risk.domain.RiskFactors;
import com.zerotrust.risk.domain.RiskFeatureExtraction;
import com.zerotrust.risk.domain.RiskReason;
import com.zerotrust.risk.feature.RiskFeatureExtractor;
import com.zerotrust.risk.rule.PrioritySecurityRule;
import com.zerotrust.risk.rule.PrioritySecurityRuleEvaluator;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class RiskEvaluationServiceTests {

    @Test
    void incompleteHistoricalDataRequiresMfa() {
        RiskFeatureExtractor extractor = context -> new RiskFeatureExtraction(
                zeroFactors(),
                RiskDataStatus.INCOMPLETE,
                List.of(RiskReason.AUTHENTICATION_HISTORY_UNAVAILABLE)
        );
        RiskEvaluationService service = evaluationService(List.of(), extractor);

        RiskEvaluation result = service.evaluate(context());

        assertThat(result.riskScore()).isNull();
        assertThat(result.dataStatus()).isEqualTo(RiskDataStatus.INCOMPLETE);
        assertThat(result.decision()).isEqualTo(RiskDecision.STEP_UP_MFA);
        assertThat(result.reasons()).containsExactly(RiskReason.AUTHENTICATION_HISTORY_UNAVAILABLE);
    }

    @Test
    void priorityRuleDeniesBeforeFeatureExtraction() {
        PrioritySecurityRule blockingRule = context -> Optional.of(RiskReason.BLOCKED_IP_ADDRESS);
        RiskFeatureExtractor extractor = context -> {
            throw new AssertionError("feature extraction must not run after a hard deny");
        };
        RiskEvaluationService service = evaluationService(List.of(blockingRule), extractor);

        RiskEvaluation result = service.evaluate(context());

        assertThat(result.riskScore()).isNull();
        assertThat(result.dataStatus()).isEqualTo(RiskDataStatus.NOT_EVALUATED);
        assertThat(result.decision()).isEqualTo(RiskDecision.DENY);
        assertThat(result.reasons()).containsExactly(RiskReason.BLOCKED_IP_ADDRESS);
    }

    private RiskEvaluationService evaluationService(
            List<PrioritySecurityRule> rules,
            RiskFeatureExtractor extractor
    ) {
        RiskPolicyProperties policy = new RiskPolicyProperties();
        RiskPolicyProperties.Weights weights = new RiskPolicyProperties.Weights();
        weights.setDevice(new BigDecimal("0.25"));
        weights.setNetwork(new BigDecimal("0.25"));
        weights.setTemporal(new BigDecimal("0.25"));
        weights.setAuthenticationHistory(new BigDecimal("0.25"));
        policy.setWeights(weights);

        RiskPolicyProperties.Thresholds thresholds = new RiskPolicyProperties.Thresholds();
        thresholds.setMediumMinimum(new BigDecimal("40"));
        thresholds.setHighMinimum(new BigDecimal("75"));
        policy.setThresholds(thresholds);

        return new RiskEvaluationService(
                new PrioritySecurityRuleEvaluator(rules),
                extractor,
                new RiskScoringService(policy)
        );
    }

    private LoginContext context() {
        return new LoginContext(
                "subject-id",
                "authentication-session-id",
                "zerotrust-spa",
                "203.0.113.10",
                "Mozilla/5.0",
                "device-123",
                Instant.parse("2026-09-04T08:00:00Z")
        );
    }

    private RiskFactors zeroFactors() {
        return new RiskFactors(BigDecimal.ZERO, BigDecimal.ZERO, BigDecimal.ZERO, BigDecimal.ZERO);
    }
}
