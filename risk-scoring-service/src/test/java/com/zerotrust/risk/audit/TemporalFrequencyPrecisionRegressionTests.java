package com.zerotrust.risk.audit;

import com.zerotrust.risk.config.TemporalRiskProperties;
import com.zerotrust.risk.domain.RiskDataStatus;
import com.zerotrust.risk.domain.RiskDecision;
import com.zerotrust.risk.domain.RiskReason;
import com.zerotrust.risk.domain.TemporalProfileStatus;
import jakarta.validation.Validation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TemporalFrequencyPrecisionRegressionTests {

    @ParameterizedTest(name = "{0}/{1} minimum={2}")
    @MethodSource("precisionCases")
    void exactIntegerOracleDeterminesTemporalScoreAndWeightedDecision(
            int matches, int size, String threshold
    ) {
        AuditRiskFixture fixture = fixture(size, matches);
        BigDecimal minimum = new BigDecimal(threshold);
        fixture.temporal.setMinimumDayFrequency(minimum);
        fixture.temporal.setMinimumHourFrequency(minimum);
        try (var factory = Validation.buildDefaultValidatorFactory()) {
            assertThat(factory.getValidator().validate(fixture.temporal)).isEmpty();
        }

        boolean below = integerOrdering(matches, size, minimum) < 0;
        var temporal = fixture.temporalCalculator().calculate(fixture.context());
        var evaluation = fixture.evaluate();
        assertThat(temporal.status()).isEqualTo(TemporalProfileStatus.AVAILABLE);
        assertThat(temporal.riskScore()).isEqualByComparingTo(below ? "100" : "0");
        // Trusted device=0, network=50, history=50, equal .25 weights, thresholds 40/75.
        assertThat(evaluation.riskScore()).isEqualByComparingTo(below ? "50" : "25");
        assertThat(evaluation.decision()).isEqualTo(below ? RiskDecision.STEP_UP_MFA : RiskDecision.ALLOW);
        assertThat(evaluation.dataStatus()).isEqualTo(RiskDataStatus.COMPLETE);
        assertThat(evaluation.reasons().contains(RiskReason.TEMPORAL_RISK)).isEqualTo(below);
    }

    static Stream<Arguments> precisionCases() {
        List<Arguments> cases = new ArrayList<>();
        for (String threshold : List.of("0.5", "0.500000", "0.333333", "0.6666668",
                "0.3333332", "0.5000000", "0.50000001", "0.49999999", "0.5000000001",
                "0.4999999999", "0.50000000000000000000000000000000000000000000000001",
                "0.49999999999999999999999999999999999999999999999999",
                "0.50000000000000000000000000000000000000000000000000")) {
            for (int matches : new int[]{2, 3, 4}) cases.add(Arguments.of(matches, 6, threshold));
        }
        for (int matches : new int[]{0, 1, 2}) cases.add(Arguments.of(matches, 8, "0.125"));
        for (String threshold : List.of("1", "1.0000000000",
                "0.99999999999999999999999999999999999999999999999999")) {
            for (int matches : new int[]{5, 6}) cases.add(Arguments.of(matches, 6, threshold));
        }
        for (int matches : new int[]{0, 1, 6}) cases.add(Arguments.of(matches, 6, "1E-50"));
        for (int matches : new int[]{0, 1, 3333, 3334, 5000, 9999, 10000}) {
            cases.add(Arguments.of(matches, 10000, "0.3333333333333333333333333333333333333333"));
        }
        cases.add(Arguments.of(1, 10000, "0.0001000000"));
        cases.add(Arguments.of(9999, 10000, "0.9999000000"));
        return cases.stream();
    }

    // Independent oracle: scale/unscaled integers, no BigDecimal multiplication/division,
    // no production helper calls and no floating-point or rounding.
    private static int integerOrdering(int matches, int size, BigDecimal threshold) {
        BigInteger left = BigInteger.valueOf(matches);
        BigInteger right = threshold.unscaledValue().multiply(BigInteger.valueOf(size));
        if (threshold.scale() >= 0) left = left.multiply(BigInteger.TEN.pow(threshold.scale()));
        else right = right.multiply(BigInteger.TEN.pow(-threshold.scale()));
        return left.compareTo(right);
    }

    @ParameterizedTest
    @ValueSource(strings = {"0.5", "0.500000", "0.5000000", "0.50000000", "0.5000000000",
            "0.50000000000000000000000000000000000000000000000000", "5E-1"})
    void equalityIsUsualRegardlessOfThresholdScale(String threshold) {
        AuditRiskFixture fixture = fixture(6, 3);
        fixture.temporal.setMinimumDayFrequency(new BigDecimal(threshold));
        fixture.temporal.setMinimumHourFrequency(new BigDecimal(threshold));
        assertThat(fixture.temporalCalculator().calculate(fixture.context()).riskScore())
                .isEqualByComparingTo("0");
    }

    @ParameterizedTest
    @ValueSource(strings = {"day", "hour"})
    void onlyOneUnusualDimensionKeepsMediumTemporalScore(String dimension) {
        AuditRiskFixture fixture = fixture(6, 3);
        fixture.temporal.setMinimumDayFrequency(new BigDecimal(dimension.equals("day")
                ? "0.50000000000000000001" : "0.5"));
        fixture.temporal.setMinimumHourFrequency(new BigDecimal(dimension.equals("hour")
                ? "0.50000000000000000001" : "0.5"));
        assertThat(fixture.temporalCalculator().calculate(fixture.context()).riskScore())
                .isEqualByComparingTo("50");
        assertThat(fixture.evaluate().riskScore()).isEqualByComparingTo("37.50");
        assertThat(fixture.evaluate().decision()).isEqualTo(RiskDecision.ALLOW);
    }

    @Test
    void defaultMinimumsRetainExactBoundariesAndDecisions() {
        for (int matches : new int[]{0, 1, 2, 10}) {
            AuditRiskFixture fixture = fixture(10, matches);
            fixture.temporal.setMinimumDayFrequency(new BigDecimal("0.10"));
            fixture.temporal.setMinimumHourFrequency(new BigDecimal("0.20"));
            assertThat(fixture.temporalCalculator().calculate(fixture.context()).riskScore())
                    .isEqualByComparingTo(matches == 0 ? "100" : matches == 1 ? "50" : "0");
            assertThat(fixture.evaluate().decision())
                    .isEqualTo(matches == 0 ? RiskDecision.STEP_UP_MFA : RiskDecision.ALLOW);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 4})
    void insufficientHistoryDoesNotAttemptAFrequencyComparison(int size) {
        AuditRiskFixture fixture = fixture(Math.max(1, size), 0);
        fixture.history = fixture.history.subList(0, size);
        fixture.temporal.setMinimumEvents(5);
        assertThat(fixture.temporalCalculator().calculate(fixture.context()).status())
                .isEqualTo(TemporalProfileStatus.COLD_START);
        var evaluation = fixture.evaluate();
        assertThat(evaluation.dataStatus()).isEqualTo(RiskDataStatus.INCOMPLETE);
        assertThat(evaluation.decision()).isEqualTo(RiskDecision.STEP_UP_MFA);
        assertThat(evaluation.riskScore()).isNull();
    }

    @Test
    void unavailableHistoryKeepsIncompleteMfaAndSecurityRevokeKeepsDenyPrecedence() {
        AuditRiskFixture fixture = fixture(6, 4);
        fixture.temporalUnavailable = true;
        assertThat(fixture.temporalCalculator().calculate(fixture.context()).status())
                .isEqualTo(TemporalProfileStatus.UNAVAILABLE);
        var unavailable = fixture.evaluate();
        assertThat(unavailable.dataStatus()).isEqualTo(RiskDataStatus.INCOMPLETE);
        assertThat(unavailable.decision()).isEqualTo(RiskDecision.STEP_UP_MFA);
        assertThat(unavailable.riskScore()).isNull();
        fixture.device = AuditRiskFixture.Device.SECURITY_REVOKED;
        assertThat(fixture.evaluate().decision()).isEqualTo(RiskDecision.DENY);
    }

    @Test
    void weightedHighRiskAndMandatoryMfaStillHavePrecedence() {
        AuditRiskFixture fixture = fixture(6, 4);
        fixture.temporal.setMinimumDayFrequency(new BigDecimal("0.6666668"));
        fixture.temporal.setMinimumHourFrequency(new BigDecimal("0.6666668"));
        fixture.ip = "203.0.113.10";
        fixture.subjectFailures = 5;
        assertThat(fixture.evaluate().riskScore()).isEqualByComparingTo("75");
        assertThat(fixture.evaluate().decision()).isEqualTo(RiskDecision.DENY);
        fixture.history = history(6, 6);
        fixture.ip = "192.0.2.1";
        fixture.subjectFailures = 3;
        fixture.device = AuditRiskFixture.Device.NEW;
        assertThat(fixture.evaluate().decision()).isEqualTo(RiskDecision.STEP_UP_MFA);
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "-0.1", "1.00000000000000000000000000000000000001"})
    void invalidMinimumsRemainRejected(String threshold) {
        var properties = AuditRiskFixture.temporalPolicy();
        properties.setMinimumDayFrequency(new BigDecimal(threshold));
        properties.setMinimumHourFrequency(new BigDecimal(threshold));
        try (var factory = Validation.buildDefaultValidatorFactory()) {
            assertThat(factory.getValidator().validate(properties))
                    .anyMatch(v -> v.getPropertyPath().toString().equals("minimumDayFrequency"))
                    .anyMatch(v -> v.getPropertyPath().toString().equals("minimumHourFrequency"));
        }
    }

    @Test
    void invalidWindowSampleRangeAndMissingThresholdRemainRejected() {
        for (String mutation : List.of("null-window", "zero-window", "negative-window",
                "zero-minimum", "negative-minimum", "over-maximum", "null-threshold")) {
            var properties = AuditRiskFixture.temporalPolicy();
            switch (mutation) {
                case "null-window" -> properties.setHistoryWindow(null);
                case "zero-window" -> properties.setHistoryWindow(Duration.ZERO);
                case "negative-window" -> properties.setHistoryWindow(Duration.ofSeconds(-1));
                case "zero-minimum" -> properties.setMinimumEvents(0);
                case "negative-minimum" -> properties.setMinimumEvents(-1);
                case "over-maximum" -> properties.setMaximumEvents(10001);
                case "null-threshold" -> properties.setMinimumDayFrequency(null);
                default -> throw new AssertionError(mutation);
            }
            try (var factory = Validation.buildDefaultValidatorFactory()) {
                assertThat(factory.getValidator().validate(properties)).as(mutation).isNotEmpty();
            }
        }
    }

    @Test
    void configurationBindingPreservesDecimalPrecisionWithoutADoubleConversion() {
        String threshold = "0.50000000000000000000000000000000000000000000000001";
        var binder = new Binder(new MapConfigurationPropertySource(Map.of(
                "risk.policy.temporal-risk.minimum-day-frequency", threshold,
                "risk.policy.temporal-risk.minimum-hour-frequency", threshold)));
        var properties = binder.bind("risk.policy.temporal-risk", Bindable.of(TemporalRiskProperties.class)).get();
        assertThat(properties.getMinimumDayFrequency()).isEqualTo(new BigDecimal(threshold));
        assertThat(properties.getMinimumHourFrequency()).isEqualTo(new BigDecimal(threshold));
    }

    @ParameterizedTest
    @ValueSource(strings = {"NaN", "Infinity", "-Infinity", "not-a-number"})
    void nonDecimalConfigurationCannotBindToAMinimum(String threshold) {
        var binder = new Binder(new MapConfigurationPropertySource(Map.of(
                "risk.policy.temporal-risk.minimum-day-frequency", threshold)));
        assertThatThrownBy(() -> binder.bind("risk.policy.temporal-risk", Bindable.of(TemporalRiskProperties.class)))
                .isInstanceOf(org.springframework.boot.context.properties.bind.BindException.class);
    }

    private static AuditRiskFixture fixture(int size, int matches) {
        var fixture = new AuditRiskFixture();
        fixture.ip = "192.0.2.1";
        fixture.subjectFailures = 3;
        fixture.temporal.setMinimumEvents(1);
        fixture.temporal.setMaximumEvents(10000);
        fixture.temporal.setHourTolerance(0);
        fixture.history = history(size, matches);
        return fixture;
    }

    private static List<Instant> history(int size, int matches) {
        List<Instant> result = new ArrayList<>();
        Instant sameDayAndHour = AuditRiskFixture.NOW.minus(Duration.ofDays(7));
        Instant differentDayAndHour = AuditRiskFixture.NOW.minus(Duration.ofDays(6)).plus(Duration.ofHours(6));
        for (int i = 0; i < size; i++) result.add(
                (i < matches ? sameDayAndHour : differentDayAndHour).plusNanos(i));
        return result;
    }
}
