package com.zerotrust.risk.config;

import com.zerotrust.risk.domain.*;
import com.zerotrust.risk.feature.RiskFeatureExtractor;
import com.zerotrust.risk.rule.PrioritySecurityRuleEvaluator;
import com.zerotrust.risk.service.RiskEvaluationService;
import com.zerotrust.risk.service.RiskScoringService;
import com.zerotrust.risk.trace.RiskScoreTrace;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class PublicDemoB0DecisionTest {
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withInitializer(new ConfigDataApplicationContextInitializer())
            .withUserConfiguration(PublicDemoB0ContractTest.PolicyBinding.class);

    @ParameterizedTest
    @CsvSource({"0,0.00,LOW,ALLOW", "39.994,39.99,LOW,ALLOW", "39.995,40.00,MEDIUM,STEP_UP_MFA",
            "40,40.00,MEDIUM,STEP_UP_MFA", "74.994,74.99,MEDIUM,STEP_UP_MFA",
            "74.995,75.00,HIGH,DENY", "75,75.00,HIGH,DENY", "100,100.00,HIGH,DENY",
            "0.004,0.00,LOW,ALLOW", "0.005,0.01,LOW,ALLOW", "99.995,100.00,HIGH,DENY"})
    void roundedScoreUsesTheApprovedBoundary(String factor, String expected, String level, String decision) {
        withScoring(scoring -> {
            var f = new BigDecimal(factor);
            RiskEvaluation result = scoring.evaluate(new RiskFactors(f, f, f, f));
            assertThat(result.riskScore()).isEqualByComparingTo(expected).hasScaleOf(2);
            assertThat(result.riskLevel().name()).isEqualTo(level);
            assertThat(result.decision().name()).isEqualTo(decision);
            assertThat(result.evaluationId()).isNotNull();
            assertThat(result.dataStatus()).isEqualTo(RiskDataStatus.COMPLETE);
        });
    }

    @ParameterizedTest
    @CsvSource({"0.01,0.00", "0.02,0.01", "100,25.00"})
    void unequalFactorsStillUseExactlyOneQuarterEach(String device, String expected) {
        withScoring(scoring -> assertThat(scoring.evaluate(new RiskFactors(new BigDecimal(device),
                BigDecimal.ZERO, BigDecimal.ZERO, BigDecimal.ZERO)).riskScore()).isEqualByComparingTo(expected));
    }

    @Test void lowScoreCannotBypassMandatoryMfaAndHighCannotBeDowngraded() {
        withScoring(scoring -> {
            var low = scoring.evaluateWithRequiredStepUp(new RiskFactors(BigDecimal.ZERO, BigDecimal.ZERO,
                    BigDecimal.ZERO, BigDecimal.valueOf(100)), List.of(RiskReason.EXCESSIVE_AUTHENTICATION_FAILURES));
            assertThat(low.riskScore()).isEqualByComparingTo("25.00");
            assertThat(low.decision()).isEqualTo(RiskDecision.STEP_UP_MFA);
            var hundred = BigDecimal.valueOf(100);
            assertThat(scoring.evaluateWithRequiredStepUp(new RiskFactors(hundred, hundred, hundred, hundred),
                    List.of(RiskReason.NEW_DEVICE)).decision()).isEqualTo(RiskDecision.DENY);
        });
    }

    @Test void priorityDenyPrecedesAllFeaturesAndHasNoScoredHigh() {
        withScoring(scoring -> {
            var rules = new PrioritySecurityRuleEvaluator(List.of(context -> Optional.of(RiskReason.BLOCKED_IP_ADDRESS)));
            RiskFeatureExtractor features = context -> { throw new AssertionError("priority must short-circuit features"); };
            var result = new RiskEvaluationService(rules, features, scoring, mock(RiskScoreTrace.class)).evaluate(login());
            assertThat(result.decision()).isEqualTo(RiskDecision.DENY);
            assertThat(result.riskScore()).isNull();
            assertThat(result.dataStatus()).isEqualTo(RiskDataStatus.NOT_EVALUATED);
        });
    }

    @Test void incompleteFeaturesCannotTurnFallbackZerosIntoLowAllow() {
        withScoring(scoring -> {
            RiskFeatureExtractor features = context -> new RiskFeatureExtraction(new RiskFactors(BigDecimal.ZERO,
                    BigDecimal.ZERO, BigDecimal.ZERO, BigDecimal.ZERO), RiskDataStatus.INCOMPLETE,
                    List.of(RiskReason.AUTHENTICATION_HISTORY_UNAVAILABLE));
            var result = new RiskEvaluationService(new PrioritySecurityRuleEvaluator(List.of()), features,
                    scoring, mock(RiskScoreTrace.class)).evaluate(login());
            assertThat(result.decision()).isEqualTo(RiskDecision.STEP_UP_MFA);
            assertThat(result.riskScore()).isNull();
            assertThat(result.dataStatus()).isEqualTo(RiskDataStatus.INCOMPLETE);
        });
    }

    private void withScoring(Consumer<RiskScoringService> check) {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            RiskPolicyProperties policy = context.getBean(RiskPolicyProperties.class);
            assertThat(policy.getModel()).isEqualTo(RiskScoreModel.BASELINE_B0);
            check.accept(new RiskScoringService(policy));
        });
    }

    private static LoginContext login() {
        return new LoginContext("subject-A", "session-A", "zerotrust-spa", "192.0.2.1", null, null,
                Instant.parse("2026-11-06T00:00:00Z"));
    }
}
