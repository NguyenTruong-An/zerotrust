package com.zerotrust.risk.audit;

import com.zerotrust.risk.config.RiskPolicyProperties;
import com.zerotrust.risk.domain.*;
import com.zerotrust.risk.service.RiskScoringService;
import jakarta.validation.Validation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.*;
import java.util.*;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

import static org.assertj.core.api.Assertions.*;

class IndependentRiskScoreAuditTests {
    @ParameterizedTest(name = "raw={0}, rounded={1}, decision={2}")
    @CsvSource({"0,0.00,ALLOW", "39.9949,39.99,ALLOW", "39.995,40.00,STEP_UP_MFA",
            "39.9999,40.00,STEP_UP_MFA", "40,40.00,STEP_UP_MFA", "40.0001,40.00,STEP_UP_MFA",
            "74.9949,74.99,STEP_UP_MFA", "74.995,75.00,DENY", "75,75.00,DENY",
            "75.0001,75.00,DENY", "100,100.00,DENY"})
    void quantizedScoreBoundaries(String raw, String rounded, RiskDecision expected) {
        RiskEvaluation actual = new RiskScoringService(AuditRiskFixture.policy("0.25","0.25","0.25","0.25"))
                .evaluate(factors(raw, raw, raw, raw));
        assertThat(actual.riskScore()).isEqualByComparingTo(rounded);
        assertDecision(actual, expected);
    }

    @Test
    void independentIntegerOracleAndCoordinateMonotonicityForValidPolicies() {
        Random random = new Random(0x01A2026L);
        for (int sample = 0; sample < 1024; sample++) {
            int[] cuts = {0, random.nextInt(10001), random.nextInt(10001), random.nextInt(10001), 10000};
            Arrays.sort(cuts);
            String[] weights = new String[4];
            BigDecimal[] input = new BigDecimal[4];
            for (int i = 0; i < 4; i++) {
                weights[i] = BigDecimal.valueOf(cuts[i+1]-cuts[i], 4).toPlainString();
                input[i] = BigDecimal.valueOf(random.nextInt(1_000_001), 4);
            }
            RiskPolicyProperties policy = AuditRiskFixture.policy(weights);
            RiskScoringService scorer = new RiskScoringService(policy);
            RiskEvaluation actual = scorer.evaluate(new RiskFactors(input[0], input[1], input[2], input[3]));
            BigDecimal expected = integerOracle(input, weights);
            assertThat(actual.riskScore()).as("seed=0x01A2026 sample=%s input=%s weights=%s", sample,
                    Arrays.toString(input), Arrays.toString(weights)).isEqualByComparingTo(expected);
            assertDecision(actual, classification(expected));
            assertThat(actual.riskScore()).isBetween(BigDecimal.ZERO, new BigDecimal("100"));
            for (int coordinate = 0; coordinate < 4; coordinate++) {
                BigDecimal[] raised = input.clone(); raised[coordinate] = new BigDecimal("100");
                RiskEvaluation after = scorer.evaluate(new RiskFactors(raised[0], raised[1], raised[2], raised[3]));
                assertThat(after.riskScore()).isGreaterThanOrEqualTo(actual.riskScore());
                assertThat(protection(after.decision())).isGreaterThanOrEqualTo(protection(actual.decision()));
            }
        }
    }

    // Product sum represented in integers; decimal rounding is implemented using quotient/remainder.
    // This oracle never calls production scoring/classification helpers.
    private BigDecimal integerOracle(BigDecimal[] input, String[] weights) {
        BigInteger numerator = BigInteger.ZERO;
        for (int i = 0; i < 4; i++) numerator = numerator.add(input[i].movePointRight(4).toBigIntegerExact()
                .multiply(new BigDecimal(weights[i]).movePointRight(4).toBigIntegerExact()));
        BigInteger divisor = BigInteger.valueOf(1_000_000); // product has scale 8; output cents scale 2
        BigInteger[] division = numerator.divideAndRemainder(divisor);
        BigInteger cents = division[0];
        if (division[1].shiftLeft(1).compareTo(divisor) >= 0) cents = cents.add(BigInteger.ONE);
        return new BigDecimal(cents, 2);
    }

    @Test
    void jointPermutationOfWeightsAndFactorsPreservesDecisionAndScore() {
        String[] weight = {"0.1", "0.2", "0.3", "0.4"};
        String[] value = {"5.1234", "87.4321", "63.2109", "12.1111"};
        // Independently: .51234 + 17.48642 + 18.96327 + 4.84444 = 41.80647.
        BigDecimal expected = new BigDecimal("41.81");
        for (int a = 0; a < 4; a++) for (int b = 0; b < 4; b++)
            for (int c = 0; c < 4; c++) for (int d = 0; d < 4; d++) {
                if (a == b || a == c || a == d || b == c || b == d || c == d) continue;
                RiskEvaluation actual = new RiskScoringService(AuditRiskFixture.policy(weight[a],weight[b],weight[c],weight[d]))
                        .evaluate(factors(value[a],value[b],value[c],value[d]));
                assertThat(actual.riskScore()).isEqualByComparingTo(expected);
                assertDecision(actual, RiskDecision.STEP_UP_MFA);
            }
    }

    @ParameterizedTest(name = "coordinate={0}, invalid={1}")
    @MethodSource("invalidFactors")
    void nullAndOutOfRangeFactorsAreRejected(int coordinate, BigDecimal invalid) {
        BigDecimal[] input = {BigDecimal.ZERO, BigDecimal.ZERO, BigDecimal.ZERO, BigDecimal.ZERO};
        input[coordinate] = invalid;
        assertThatThrownBy(() -> new RiskFactors(input[0],input[1],input[2],input[3]))
                .isInstanceOf(invalid == null ? NullPointerException.class : IllegalArgumentException.class);
    }

    static Stream<Arguments> invalidFactors() {
        List<Arguments> cases = new ArrayList<>();
        for (int i = 0; i < 4; i++) for (BigDecimal invalid : new BigDecimal[]{null,
                new BigDecimal("-0.0001"), new BigDecimal("100.0001")}) cases.add(Arguments.of(i, invalid));
        return cases.stream();
    }

    @ParameterizedTest
    @CsvSource({"zero-sum", "excess-sum", "negative", "null-weight", "null-weights",
            "equal-threshold", "reverse-threshold", "negative-threshold", "null-threshold", "over-100"})
    void invalidPolicyCannotPassBeanValidation(String mutation) {
        RiskPolicyProperties p = AuditRiskFixture.policy("0.25","0.25","0.25","0.25");
        switch (mutation) {
            case "zero-sum" -> p.getWeights().setDevice(BigDecimal.ZERO);
            case "excess-sum" -> p.getWeights().setDevice(BigDecimal.ONE);
            case "negative" -> p.getWeights().setDevice(new BigDecimal("-0.1"));
            case "null-weight" -> p.getWeights().setDevice(null);
            case "null-weights" -> p.setWeights(null);
            case "equal-threshold" -> p.getThresholds().setMediumMinimum(new BigDecimal("75"));
            case "reverse-threshold" -> p.getThresholds().setMediumMinimum(new BigDecimal("80"));
            case "negative-threshold" -> p.getThresholds().setMediumMinimum(new BigDecimal("-1"));
            case "null-threshold" -> p.setThresholds(null);
            case "over-100" -> p.getThresholds().setHighMinimum(new BigDecimal("100.1"));
            default -> throw new AssertionError(mutation);
        }
        try (var factory = Validation.buildDefaultValidatorFactory()) {
            assertThat(factory.getValidator().validate(p)).as(mutation).isNotEmpty();
        }
    }

    @Test
    void thresholdValuesAreParametersIncludingZeroAndHundredEndpoints() {
        RiskPolicyProperties p = AuditRiskFixture.policy("1","0","0","0");
        p.getThresholds().setMediumMinimum(BigDecimal.ZERO);
        p.getThresholds().setHighMinimum(new BigDecimal("100"));
        assertDecision(new RiskScoringService(p).evaluate(factors("0","0","0","0")), RiskDecision.STEP_UP_MFA);
        assertDecision(new RiskScoringService(p).evaluate(factors("99.99","0","0","0")), RiskDecision.STEP_UP_MFA);
        assertDecision(new RiskScoringService(p).evaluate(factors("100","0","0","0")), RiskDecision.DENY);
    }

    static RiskFactors factors(String... values) {
        return new RiskFactors(new BigDecimal(values[0]),new BigDecimal(values[1]),
                new BigDecimal(values[2]),new BigDecimal(values[3]));
    }
    static RiskDecision classification(BigDecimal score) {
        return score.compareTo(new BigDecimal("40")) < 0 ? RiskDecision.ALLOW :
                score.compareTo(new BigDecimal("75")) < 0 ? RiskDecision.STEP_UP_MFA : RiskDecision.DENY;
    }
    static int protection(RiskDecision decision) {
        return switch (decision) {case ALLOW -> 0; case STEP_UP_MFA -> 1; case DENY -> 2;};
    }
    static void assertDecision(RiskEvaluation actual, RiskDecision expected) {
        assertThat(actual.decision()).isEqualTo(expected);
        assertThat(actual.riskLevel()).isEqualTo(switch(expected) {
            case ALLOW -> RiskLevel.LOW; case STEP_UP_MFA -> RiskLevel.MEDIUM; case DENY -> RiskLevel.HIGH;
        });
    }
}
