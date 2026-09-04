package com.zerotrust.risk.service;

import com.zerotrust.risk.config.RiskPolicyProperties;
import com.zerotrust.risk.domain.RiskDataStatus;
import com.zerotrust.risk.domain.RiskDecision;
import com.zerotrust.risk.domain.RiskEvaluation;
import com.zerotrust.risk.domain.RiskFactors;
import com.zerotrust.risk.domain.RiskLevel;
import com.zerotrust.risk.domain.RiskReason;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

import static org.assertj.core.api.Assertions.assertThat;

class RiskScoringServiceTests {

    private RiskScoringService service;

    @BeforeEach
    void setUp() {
        service = new RiskScoringService(testPolicy());
    }

    @Test
    void returnsAllowForLowRisk() {
        RiskEvaluation result = service.evaluate(factors("10", "20", "30", "40"));

        assertThat(result.riskScore()).isEqualByComparingTo("25.00");
        assertThat(result.riskLevel()).isEqualTo(RiskLevel.LOW);
        assertThat(result.decision()).isEqualTo(RiskDecision.ALLOW);
        assertThat(result.dataStatus()).isEqualTo(RiskDataStatus.COMPLETE);
    }

    @Test
    void returnsStepUpMfaForMediumRisk() {
        RiskEvaluation result = service.evaluate(factors("40", "50", "60", "70"));

        assertThat(result.riskScore()).isEqualByComparingTo("55.00");
        assertThat(result.riskLevel()).isEqualTo(RiskLevel.MEDIUM);
        assertThat(result.decision()).isEqualTo(RiskDecision.STEP_UP_MFA);
    }

    @Test
    void returnsDenyForHighRisk() {
        RiskEvaluation result = service.evaluate(factors("80", "80", "80", "80"));

        assertThat(result.riskScore()).isEqualByComparingTo("80.00");
        assertThat(result.riskLevel()).isEqualTo(RiskLevel.HIGH);
        assertThat(result.decision()).isEqualTo(RiskDecision.DENY);
    }

    @Test
    void returnsDenyForPriorityRuleWithoutCalculatingScore() {
        RiskEvaluation result = service.denyForPriorityRule(RiskReason.BLOCKED_IP_ADDRESS);

        assertThat(result.riskScore()).isNull();
        assertThat(result.riskLevel()).isEqualTo(RiskLevel.HIGH);
        assertThat(result.decision()).isEqualTo(RiskDecision.DENY);
        assertThat(result.reasons()).containsExactly(RiskReason.BLOCKED_IP_ADDRESS);
    }

    private RiskFactors factors(
            String device,
            String network,
            String temporal,
            String authenticationHistory
    ) {
        return new RiskFactors(
                new BigDecimal(device),
                new BigDecimal(network),
                new BigDecimal(temporal),
                new BigDecimal(authenticationHistory)
        );
    }

    private RiskPolicyProperties testPolicy() {
        RiskPolicyProperties properties = new RiskPolicyProperties();

        RiskPolicyProperties.Weights weights = new RiskPolicyProperties.Weights();
        weights.setDevice(new BigDecimal("0.25"));
        weights.setNetwork(new BigDecimal("0.25"));
        weights.setTemporal(new BigDecimal("0.25"));
        weights.setAuthenticationHistory(new BigDecimal("0.25"));
        properties.setWeights(weights);

        RiskPolicyProperties.Thresholds thresholds = new RiskPolicyProperties.Thresholds();
        thresholds.setMediumMinimum(new BigDecimal("40"));
        thresholds.setHighMinimum(new BigDecimal("75"));
        properties.setThresholds(thresholds);

        return properties;
    }
}
