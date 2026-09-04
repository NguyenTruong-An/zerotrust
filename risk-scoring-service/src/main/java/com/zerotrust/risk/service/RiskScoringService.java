package com.zerotrust.risk.service;

import com.zerotrust.risk.config.RiskPolicyProperties;
import com.zerotrust.risk.domain.RiskDecision;
import com.zerotrust.risk.domain.RiskDataStatus;
import com.zerotrust.risk.domain.RiskEvaluation;
import com.zerotrust.risk.domain.RiskFactors;
import com.zerotrust.risk.domain.RiskLevel;
import com.zerotrust.risk.domain.RiskReason;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
public class RiskScoringService {

    private static final BigDecimal ZERO = BigDecimal.ZERO;

    private final RiskPolicyProperties policy;

    public RiskScoringService(RiskPolicyProperties policy) {
        this.policy = policy;
    }

    public RiskEvaluation evaluate(RiskFactors factors) {
        BigDecimal score = weightedScore(factors);
        RiskLevel level = classify(score);

        return new RiskEvaluation(
                UUID.randomUUID(),
                score,
                level,
                decisionFor(level),
                RiskDataStatus.COMPLETE,
                reasonsFor(factors),
                Instant.now()
        );
    }

    public RiskEvaluation stepUpForIncompleteData(List<RiskReason> reasons) {
        return new RiskEvaluation(
                UUID.randomUUID(),
                null,
                RiskLevel.MEDIUM,
                RiskDecision.STEP_UP_MFA,
                RiskDataStatus.INCOMPLETE,
                reasons,
                Instant.now()
        );
    }

    public RiskEvaluation denyForPriorityRule(RiskReason reason) {
        return new RiskEvaluation(
                UUID.randomUUID(),
                null,
                RiskLevel.HIGH,
                RiskDecision.DENY,
                RiskDataStatus.NOT_EVALUATED,
                List.of(reason),
                Instant.now()
        );
    }

    private BigDecimal weightedScore(RiskFactors factors) {
        RiskPolicyProperties.Weights weights = policy.getWeights();

        return factors.deviceRisk().multiply(weights.getDevice())
                .add(factors.networkRisk().multiply(weights.getNetwork()))
                .add(factors.temporalRisk().multiply(weights.getTemporal()))
                .add(factors.authenticationHistoryRisk().multiply(weights.getAuthenticationHistory()))
                .setScale(2, RoundingMode.HALF_UP);
    }

    private RiskLevel classify(BigDecimal score) {
        RiskPolicyProperties.Thresholds thresholds = policy.getThresholds();

        if (score.compareTo(thresholds.getHighMinimum()) >= 0) {
            return RiskLevel.HIGH;
        }
        if (score.compareTo(thresholds.getMediumMinimum()) >= 0) {
            return RiskLevel.MEDIUM;
        }
        return RiskLevel.LOW;
    }

    private RiskDecision decisionFor(RiskLevel level) {
        return switch (level) {
            case LOW -> RiskDecision.ALLOW;
            case MEDIUM -> RiskDecision.STEP_UP_MFA;
            case HIGH -> RiskDecision.DENY;
        };
    }

    private List<RiskReason> reasonsFor(RiskFactors factors) {
        List<RiskReason> reasons = new ArrayList<>();
        addIfPositive(reasons, factors.deviceRisk(), RiskReason.DEVICE_RISK);
        addIfPositive(reasons, factors.networkRisk(), RiskReason.NETWORK_RISK);
        addIfPositive(reasons, factors.temporalRisk(), RiskReason.TEMPORAL_RISK);
        addIfPositive(
                reasons,
                factors.authenticationHistoryRisk(),
                RiskReason.AUTHENTICATION_HISTORY_RISK
        );
        return reasons;
    }

    private void addIfPositive(List<RiskReason> reasons, BigDecimal score, RiskReason reason) {
        if (score.compareTo(ZERO) > 0) {
            reasons.add(reason);
        }
    }
}
