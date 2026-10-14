package com.zerotrust.risk.audit;

import com.zerotrust.risk.domain.*;
import jakarta.validation.Validation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;

import java.math.BigDecimal;
import java.time.*;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static com.zerotrust.risk.audit.IndependentRiskScoreAuditTests.*;

class IndependentTemporalAuditTests {
    @ParameterizedTest(name = "matches={0}/6 threshold={1} expectedDecision={2}")
    @CsvSource({"4,0.6666668,STEP_UP_MFA", "2,0.3333332,ALLOW"})
    void exactFrequencyComparisonMustNotBeReversedByRounding(int matches, String threshold,
                                                            RiskDecision expectedDecision) {
        AuditRiskFixture f = new AuditRiskFixture();
        f.ip = "192.0.2.1"; f.subjectFailures = 3; // default network 50 + history 50; no mandatory MFA
        f.history = AuditRiskFixture.history(6, matches);
        f.temporal.setMinimumDayFrequency(new BigDecimal(threshold));
        f.temporal.setMinimumHourFrequency(new BigDecimal(threshold));
        try (var factory = Validation.buildDefaultValidatorFactory()) {
            assertThat(factory.getValidator().validate(f.temporal)).isEmpty();
        }
        // Compare integers against threshold * sample, avoiding division or rounded frequencies.
        boolean unusual = BigDecimal.valueOf(matches).compareTo(new BigDecimal(threshold)
                .multiply(BigDecimal.valueOf(6))) < 0;
        BigDecimal expectedTemporal = unusual ? new BigDecimal("100") : BigDecimal.ZERO;
        RiskEvaluation actual = f.evaluate();
        BigDecimal actualTemporal = f.temporalCalculator().calculate(f.context()).riskScore();
        System.out.printf(Locale.ROOT,
                "AUDIT TEMPORAL matches=%d/6 threshold=%s expectedTemporal=%s actualTemporal=%s expected=%s actual=%s score=%s%n",
                matches,threshold,expectedTemporal,actualTemporal,expectedDecision,actual.decision(),actual.riskScore());
        assertThat(actualTemporal).as("exact rational %s/6 vs %s", matches,threshold)
                .isEqualByComparingTo(expectedTemporal);
        assertDecision(actual, expectedDecision);
    }

    @Test
    void exactOracleAtOrdinaryFrequencyBoundariesAndAllMatchCounts() {
        for (String threshold : List.of("0.10", "0.20", "0.5", "1")) for (int matches = 0; matches <= 6; matches++) {
            AuditRiskFixture f = new AuditRiskFixture(); f.history = AuditRiskFixture.history(6,matches);
            f.temporal.setMinimumDayFrequency(new BigDecimal(threshold));
            f.temporal.setMinimumHourFrequency(new BigDecimal(threshold));
            boolean unusual = BigDecimal.valueOf(matches).compareTo(new BigDecimal(threshold)
                    .multiply(BigDecimal.valueOf(6))) < 0;
            assertThat(f.temporalCalculator().calculate(f.context()).riskScore())
                    .as("matches=%s threshold=%s", matches,threshold).isEqualByComparingTo(unusual ? "100" : "0");
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 12})
    void everyHourPairUsesIndependentCircularNeighborhoodOracle(int tolerance) {
        for (int currentHour = 0; currentHour < 24; currentHour++) for (int priorHour = 0; priorHour < 24; priorHour++) {
            AuditRiskFixture f = new AuditRiskFixture(); f.temporal.setHourTolerance(tolerance);
            f.now = AuditRiskFixture.NOW.minus(Duration.ofHours(8)).plus(Duration.ofHours(currentHour));
            f.history = new ArrayList<>();
            for (int week = 1; week <= 6; week++) f.history.add(AuditRiskFixture.NOW.minus(Duration.ofHours(8))
                    .minus(Duration.ofDays(7L*week)).plus(Duration.ofHours(priorHour)));
            Set<Integer> accepted = new HashSet<>();
            for (int offset = -tolerance; offset <= tolerance; offset++) accepted.add(Math.floorMod(currentHour+offset,24));
            assertThat(f.temporalCalculator().calculate(f.context()).riskScore())
                    .as("current=%s history=%s tolerance=%s", currentHour,priorHour,tolerance)
                    .isEqualByComparingTo(accepted.contains(priorHour) ? "0" : "50");
        }
    }

    @Test
    void historyPermutationAndReplicationPreserveFrequenciesOnceProfileIsAvailable() {
        AuditRiskFixture f = new AuditRiskFixture(); f.history = AuditRiskFixture.history(6,2);
        BigDecimal before = f.temporalCalculator().calculate(f.context()).riskScore();
        Collections.reverse(f.history);
        assertThat(f.temporalCalculator().calculate(f.context()).riskScore()).isEqualByComparingTo(before);
        List<Instant> replicated = new ArrayList<>(f.history); replicated.addAll(f.history);
        f.history = replicated;
        assertThat(f.temporalCalculator().calculate(f.context()).riskScore()).isEqualByComparingTo(before);
    }

    @ParameterizedTest
    @ValueSource(ints = {4, 5, 6})
    void coldStartEndsExactlyAtMinimumSampleSize(int count) {
        AuditRiskFixture f = new AuditRiskFixture(); f.history = AuditRiskFixture.history(count,count);
        TemporalRiskAssessment actual = f.temporalCalculator().calculate(f.context());
        assertThat(actual.status()).isEqualTo(count < 5 ? TemporalProfileStatus.COLD_START : TemporalProfileStatus.AVAILABLE);
        assertDecision(f.evaluate(), count < 5 ? RiskDecision.STEP_UP_MFA : RiskDecision.ALLOW);
    }

    @ParameterizedTest
    @ValueSource(strings = {"2026-03-29T03:30:00+02:00[Europe/Berlin]",
            "2026-10-25T02:30:00+01:00[Europe/Berlin]"})
    void dstTransitionsCompareConfiguredLocalWallHour(String current) {
        AuditRiskFixture f = new AuditRiskFixture();
        ZonedDateTime local = ZonedDateTime.parse(current);
        f.now = local.toInstant(); f.temporal.setZoneId(local.getZone()); f.temporal.setHourTolerance(0);
        f.history = new ArrayList<>();
        for (int week = 1; week <= 6; week++) f.history.add(local.minusWeeks(week).toInstant());
        assertThat(f.temporalCalculator().calculate(f.context()).riskScore()).isEqualByComparingTo("0");
    }
}
