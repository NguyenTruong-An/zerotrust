package com.zerotrust.risk.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.risk.domain.*;
import com.zerotrust.risk.service.RiskScoringService;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * OFFLINE RESEARCH ONLY. No Spring context, HTTP, Docker, database or Redis writes.
 * Reuses the existing in-memory I/O fixture; production extraction/calculators/scoring are real.
 * The candidate functions below are a proposed experiment, never production scoring.
 * Generated aggregates/CSV contain synthetic factors only and stay under ignored target/.
 */
class TrustScoreResearchTests {
    private static final BigDecimal HUNDRED = new BigDecimal("100");

    @Test
    void researchFixtureMatchesSourceNumericDefaults() throws IOException {
        Properties p = new Properties();
        try (var input = getClass().getResourceAsStream("/application.properties")) {
            Objects.requireNonNull(input);
            p.load(input);
        }
        Map<String, String> expected = Map.ofEntries(
                Map.entry("weights.device", "0.25"), Map.entry("weights.network", "0.25"),
                Map.entry("weights.temporal", "0.25"), Map.entry("weights.authentication-history", "0.25"),
                Map.entry("thresholds.medium-minimum", "40"), Map.entry("thresholds.high-minimum", "75"),
                Map.entry("device-risk.missing", "80"), Map.entry("device-risk.new-device", "60"),
                Map.entry("device-risk.pending", "50"), Map.entry("device-risk.trusted", "0"),
                Map.entry("device-risk.revoked", "100"),
                Map.entry("authentication-history-risk.subject-medium-minimum", "3"),
                Map.entry("authentication-history-risk.subject-high-minimum", "5"),
                Map.entry("authentication-history-risk.source-ip-medium-minimum", "10"),
                Map.entry("authentication-history-risk.source-ip-high-minimum", "20"),
                Map.entry("authentication-history-risk.medium-score", "50"),
                Map.entry("authentication-history-risk.high-score", "100"),
                Map.entry("temporal-risk.minimum-events", "5"),
                Map.entry("temporal-risk.minimum-day-frequency", "0.10"),
                Map.entry("temporal-risk.minimum-hour-frequency", "0.20"),
                Map.entry("temporal-risk.medium-score", "50"), Map.entry("temporal-risk.high-score", "100"),
                Map.entry("network-risk.default-score", "50"), Map.entry("network-risk.high-score", "100"));
        var placeholder = Pattern.compile("\\$\\{[^:}]+:([^}]+)}");
        expected.forEach((key, value) -> {
            var matcher = placeholder.matcher(p.getProperty("risk.policy." + key));
            assertThat(matcher.matches()).as(key).isTrue();
            assertThat(matcher.group(1)).as(key).isEqualTo(value);
        });
    }

    @Test
    void a5IsScoredMediumWithoutMandatoryGuard() {
        AuditRiskFixture f = fixture(AuditRiskFixture.Device.TRUSTED, 50, 100, 3);
        var extraction = f.extractor().extract(f.context());
        assertThat(extraction.priorityViolation()).isEmpty();
        assertThat(extraction.mandatoryStepUpReason()).isEmpty();
        assertThat(extraction.dataStatus()).isEqualTo(RiskDataStatus.COMPLETE);
        assertResult(f.evaluate(), "50.00", RiskLevel.MEDIUM, RiskDecision.STEP_UP_MFA);
    }

    @Test
    void a6HighIsFromNumericThresholdEvenWhenMandatorySignalsAreAlsoPresent() {
        AuditRiskFixture f = fixture(AuditRiskFixture.Device.TRUSTED, 100, 100, 5);
        var extraction = f.extractor().extract(f.context());
        assertThat(extraction.priorityViolation()).isEmpty();
        assertThat(extraction.mandatoryStepUpReason()).isPresent();
        assertResult(f.evaluate(), "75.00", RiskLevel.HIGH, RiskDecision.DENY);
        // Removing only the mandatory decision wrapper still gives numeric HIGH, not priority DENY.
        assertResult(new RiskScoringService(f.policy).evaluate(extraction.factors()),
                "75.00", RiskLevel.HIGH, RiskDecision.DENY);
        assertResult(fixture(AuditRiskFixture.Device.TRUSTED, 50, 100, 5).evaluate(),
                "62.50", RiskLevel.MEDIUM, RiskDecision.STEP_UP_MFA);
    }

    @Test
    void syntheticFactorialGridExportsActualPipelineAndCandidateComparison() throws IOException {
        List<Map<String, Object>> rows = new ArrayList<>();
        Map<String, Integer> baselineActions = new TreeMap<>(), candidateActions = new TreeMap<>();
        Map<String, Integer> unguardedActions = new TreeMap<>();
        SortedSet<BigDecimal> unguardedScores = new TreeSet<>();
        int changed = 0, priority = 0, unguarded = 0, numericHigh = 0;
        for (var device : AuditRiskFixture.Device.values()) {
            for (int network : new int[]{0, 50, 100}) {
                for (int temporal : new int[]{0, 50, 100}) {
                    for (int failures : new int[]{0, 3, 5}) {
                        AuditRiskFixture f = fixture(device, network, temporal, failures);
                        var x = f.extractor().extract(f.context());
                        RiskEvaluation result = f.evaluate();
                        BigDecimal candidateScore = x.priorityViolation().isPresent() ? null
                                : candidate(x.factors().deviceRisk(), network,
                                    temporal == 0 ? 1.0 : temporal == 50 ? 1.0 : 0.0,
                                    temporal == 0 ? 1.0 : 0.0, failures, 0);
                        RiskDecision candidateAction = candidateDecision(candidateScore,
                                x.priorityViolation().isPresent(), x.mandatoryStepUpReason().isPresent());
                        baselineActions.merge(result.decision().name(), 1, Integer::sum);
                        candidateActions.merge(candidateAction.name(), 1, Integer::sum);
                        if (result.decision() != candidateAction) changed++;
                        if (x.priorityViolation().isPresent()) {
                            priority++;
                            assertThat(result.riskScore()).isNull();
                        } else {
                            assertThat(x.dataStatus()).isEqualTo(RiskDataStatus.COMPLETE);
                            BigDecimal oracle = x.factors().deviceRisk()
                                    .add(BigDecimal.valueOf(network + temporal))
                                    .add(x.factors().authenticationHistoryRisk())
                                    .divide(new BigDecimal("4"), 2, RoundingMode.HALF_UP);
                            assertThat(result.riskScore()).isEqualByComparingTo(oracle);
                            if (result.riskLevel() == RiskLevel.HIGH) numericHigh++;
                            if (x.mandatoryStepUpReason().isEmpty()) {
                                unguarded++;
                                unguardedScores.add(result.riskScore());
                                unguardedActions.merge(result.decision().name(), 1, Integer::sum);
                            }
                        }
                        Map<String, Object> row = new LinkedHashMap<>();
                        row.put("device", device.name()); row.put("device_score", x.factors().deviceRisk());
                        row.put("network", network); row.put("temporal", temporal);
                        row.put("subject_failures", failures); row.put("ip_failures", 0);
                        row.put("priority", x.priorityViolation().isPresent());
                        row.put("mandatory", x.mandatoryStepUpReason().isPresent());
                        row.put("baseline_score", result.riskScore()); row.put("baseline_action", result.decision());
                        row.put("candidate_score", candidateScore); row.put("candidate_action", candidateAction);
                        rows.add(row);
                    }
                }
            }
        }
        assertThat(rows).hasSize(189);
        assertThat(priority).isEqualTo(27);
        assertThat(unguarded).isEqualTo(12);
        assertThat(unguardedScores.last()).isEqualByComparingTo("50");
        assertThat(unguardedActions).doesNotContainKey("DENY");
        // At these extreme/anchor values the proposed normalization is deliberately identical.
        assertThat(changed).isZero();
        Path directory = Path.of("target", "research");
        Files.createDirectories(directory);
        List<String> csv = new ArrayList<>();
        csv.add(String.join(",", rows.get(0).keySet()));
        rows.forEach(row -> csv.add(row.values().stream().map(v -> v == null ? "" : v.toString())
                .reduce((a, b) -> a + "," + b).orElseThrow()));
        Files.write(directory.resolve("baseline-candidate-grid.csv"), csv, StandardCharsets.UTF_8);
        new ObjectMapper().writerWithDefaultPrettyPrinter().writeValue(
                directory.resolve("baseline-summary.json").toFile(), Map.of(
                        "data_kind", "SYNTHETIC_CONTROLLED_OFFLINE", "cases", rows.size(),
                        "baseline_actions", baselineActions, "candidate_actions", candidateActions,
                        "priority_cases", priority, "numeric_high_cases", numericHigh,
                        "unguarded_cases", unguarded, "unguarded_scores", unguardedScores,
                        "unguarded_actions", unguardedActions, "changed_decisions", changed));
    }

    @Test
    void everyMissingFeatureCombinationIsIncompleteAndPriorityStillWins() {
        for (int unavailableMask = 1; unavailableMask < 8; unavailableMask++) {
            AuditRiskFixture f = fixture(AuditRiskFixture.Device.TRUSTED, 100, 100, 5);
            f.failedCounter = (unavailableMask & 1) != 0 ? 1 : 0;
            f.network.setEnabled((unavailableMask & 2) == 0);
            f.temporalUnavailable = (unavailableMask & 4) != 0;
            var result = f.evaluate();
            assertThat(result.riskScore()).isNull();
            assertThat(result.dataStatus()).isEqualTo(RiskDataStatus.INCOMPLETE);
            assertThat(result.decision()).isEqualTo(RiskDecision.STEP_UP_MFA);
            f.device = AuditRiskFixture.Device.SECURITY_REVOKED;
            var denied = f.evaluate();
            assertThat(denied.riskScore()).isNull();
            assertThat(denied.dataStatus()).isEqualTo(RiskDataStatus.NOT_EVALUATED);
            assertThat(denied.decision()).isEqualTo(RiskDecision.DENY);
        }
    }

    @Test
    void continuousArithmeticBoundaryProbesAreDistinctFromReachableDiscreteFeatures() {
        RiskScoringService scoring = new RiskScoringService(AuditRiskFixture.policy("0.25", "0.25", "0.25", "0.25"));
        String[] raw = {"39.99", "40", "74.99", "75", "39.995", "74.995"};
        String[] rounded = {"39.99", "40.00", "74.99", "75.00", "40.00", "75.00"};
        RiskDecision[] expected = {RiskDecision.ALLOW, RiskDecision.STEP_UP_MFA,
                RiskDecision.STEP_UP_MFA, RiskDecision.DENY, RiskDecision.STEP_UP_MFA, RiskDecision.DENY};
        for (int i = 0; i < raw.length; i++) {
            BigDecimal value = new BigDecimal(raw[i]);
            var actual = scoring.evaluate(new RiskFactors(value, value, value, value));
            assertThat(actual.riskScore()).isEqualByComparingTo(rounded[i]);
            assertThat(actual.decision()).isEqualTo(expected[i]);
        }
    }

    @Test
    void candidateIsBoundedMonotonicAnchoredAndHasSmallerLocalBandJumps() {
        assertThat(historyCandidate(0, 3, 5)).isZero();
        assertThat(historyCandidate(3, 3, 5)).isEqualTo(50.0);
        assertThat(historyCandidate(5, 3, 5)).isEqualTo(100.0);
        double previous = 0, maxJump = 0;
        for (int count = 0; count <= 30; count++) {
            double current = historyCandidate(count, 3, 5);
            assertThat(current).isBetween(0.0, 100.0).isGreaterThanOrEqualTo(previous);
            maxJump = Math.max(maxJump, current - previous); previous = current;
        }
        assertThat(maxJump).isEqualTo(25.0); // baseline subject-band maximum is 50.
        assertThat(temporalCandidate(0, 0)).isEqualTo(100.0);
        assertThat(temporalCandidate(0.1, 0.2)).isZero();
        assertThat(temporalCandidate(0.1, 0.1999)).isCloseTo(0.025,
                org.assertj.core.data.Offset.offset(0.000001));
        assertThat(candidate(BigDecimal.ZERO, 50, 0.1, 0.1999, 2, 0))
                .isEqualByComparingTo("20.84");
        for (int day = 0; day <= 100; day++) {
            double previousTemporal = 100;
            for (int hour = 0; hour <= 100; hour++) {
                double score = temporalCandidate(day / 100.0, hour / 100.0);
                assertThat(score).isBetween(0.0, 100.0).isLessThanOrEqualTo(previousTemporal);
                previousTemporal = score;
            }
        }
        // A smoother score does not imply fewer MFA decisions: this constructed case escalates.
        assertThat(candidate(BigDecimal.ZERO, 50, 0, 0, 2, 0)).isEqualByComparingTo("45.83");
    }

    @Test
    void missingnessBoundsRetainUncertaintyInsteadOfRenormalizingKnownWeights() {
        // Known contributions: N=50 with .25 weight ->12.5. Three unknown factors -> width75.
        BigDecimal lowerRisk = new BigDecimal("12.5"), unknownWeight = new BigDecimal("0.75");
        BigDecimal upperRisk = lowerRisk.add(unknownWeight.multiply(HUNDRED));
        assertThat(HUNDRED.subtract(upperRisk)).isEqualByComparingTo("12.5");
        assertThat(HUNDRED.subtract(lowerRisk)).isEqualByComparingTo("87.5");
        assertThat(candidateDecision(null, false, false)).isEqualTo(RiskDecision.STEP_UP_MFA);
        assertThat(candidateDecision(null, true, false)).isEqualTo(RiskDecision.DENY);
        assertThat(candidateDecision(BigDecimal.ZERO, false, true)).isEqualTo(RiskDecision.STEP_UP_MFA);
        assertThat(candidateDecision(new BigDecimal("75"), false, true)).isEqualTo(RiskDecision.DENY);
    }

    @Test
    void granularBehaviorSliceMeasuresDifferencesWithoutClaimingAttackAccuracy() throws IOException {
        List<String> csv = new ArrayList<>(List.of("device,network,day_matches,hour_matches,events,subject_failures,baseline_score,candidate_score,baseline_action,candidate_action"));
        Map<String, Integer> baselineActions = new TreeMap<>(), candidateActions = new TreeMap<>();
        int changed = 0, total = 0;
        BigDecimal differenceSum = BigDecimal.ZERO, maximumDifference = BigDecimal.ZERO;
        for (var device : List.of(AuditRiskFixture.Device.TRUSTED, AuditRiskFixture.Device.MISSING,
                AuditRiskFixture.Device.SECURITY_REVOKED)) {
            for (int network : new int[]{0, 50, 100}) {
                for (int days : new int[]{0, 1, 2, 3, 20}) {
                    for (int hours : new int[]{0, 3, 4, 5, 20}) {
                        for (int failures = 0; failures <= 6; failures++) {
                            AuditRiskFixture f = fixture(device, network, 0, failures);
                            List<java.time.Instant> times = new ArrayList<>();
                            for (int i = 0; i < 20; i++) {
                                // All events are inside 90 days and before the fixed evaluation time.
                                var t = AuditRiskFixture.NOW.minusSeconds(7L * (i / 4 + 1) * 86400)
                                        .minusSeconds((i % 4) * 60L);
                                if (i >= days) t = t.plusSeconds(86400);
                                if (i >= hours) t = t.plusSeconds(6 * 3600);
                                times.add(t);
                            }
                            f.history = times;
                            var x = f.extractor().extract(f.context());
                            RiskEvaluation baseline = f.evaluate();
                            BigDecimal proposed = x.priorityViolation().isPresent() ? null
                                    : candidate(x.factors().deviceRisk(), network, days / 20.0,
                                                hours / 20.0, failures, 0);
                            RiskDecision proposedAction = candidateDecision(proposed,
                                    x.priorityViolation().isPresent(), x.mandatoryStepUpReason().isPresent());
                            baselineActions.merge(baseline.decision().name(), 1, Integer::sum);
                            candidateActions.merge(proposedAction.name(), 1, Integer::sum);
                            if (baseline.decision() != proposedAction) changed++;
                            if (proposed != null) {
                                BigDecimal difference = proposed.subtract(baseline.riskScore()).abs();
                                differenceSum = differenceSum.add(difference);
                                maximumDifference = maximumDifference.max(difference);
                            }
                            total++;
                            csv.add(String.join(",", device.name(), "" + network, "" + days, "" + hours,
                                    "20", "" + failures,
                                    baseline.riskScore() == null ? "" : baseline.riskScore().toPlainString(),
                                    proposed == null ? "" : proposed.toPlainString(),
                                    baseline.decision().name(), proposedAction.name()));
                        }
                    }
                }
            }
        }
        assertThat(total).isEqualTo(1575);
        assertThat(changed).isPositive();
        int numericCases = 1050; // Two non-priority device statuses, other dimensions unchanged.
        Path directory = Path.of("target", "research");
        Files.createDirectories(directory);
        Files.write(directory.resolve("granular-behavior-grid.csv"), csv, StandardCharsets.UTF_8);
        new ObjectMapper().writerWithDefaultPrettyPrinter().writeValue(
                directory.resolve("granular-summary.json").toFile(), Map.of(
                        "data_kind", "SYNTHETIC_CONTROLLED_OFFLINE", "cases", total,
                        "numeric_cases", numericCases, "baseline_actions", baselineActions,
                        "candidate_actions", candidateActions, "changed_decisions", changed,
                        "mean_absolute_score_difference_numeric_cases", differenceSum.divide(
                                BigDecimal.valueOf(numericCases), 4, RoundingMode.HALF_UP),
                        "maximum_absolute_score_difference", maximumDifference));
    }

    private static AuditRiskFixture fixture(AuditRiskFixture.Device device, int network, int temporal, int failures) {
        AuditRiskFixture f = new AuditRiskFixture();
        f.device = device; f.subjectFailures = failures;
        // Reserved documentation addresses; no packets or network connections are made.
        f.ip = network == 0 ? "10.1.2.3" : network == 50 ? "198.51.100.17" : "203.0.113.17";
        f.history = temporal == 0 ? AuditRiskFixture.history(6, 6)
                : temporal == 100 ? AuditRiskFixture.history(6, 0)
                : AuditRiskFixture.history(6, 6).stream().map(t -> t.plusSeconds(6 * 3600)).toList();
        return f;
    }

    private static void assertResult(RiskEvaluation actual, String score, RiskLevel level, RiskDecision decision) {
        assertThat(actual.riskScore()).isEqualByComparingTo(score);
        assertThat(actual.riskLevel()).isEqualTo(level);
        assertThat(actual.decision()).isEqualTo(decision);
        assertThat(actual.dataStatus()).isEqualTo(RiskDataStatus.COMPLETE);
    }

    // Proposed B1 research functions. Knots/normalization anchors reuse baseline parameters.
    private static double historyCandidate(long count, long medium, long high) {
        return 50.0 * Math.min((double) count / medium, 1.0)
                + 50.0 * Math.max(0, Math.min((double) (count - medium) / (high - medium), 1.0));
    }

    private static double temporalCandidate(double dayFrequency, double hourFrequency) {
        return 50.0 * (Math.max(0, 1 - dayFrequency / 0.10)
                + Math.max(0, 1 - hourFrequency / 0.20));
    }

    private static BigDecimal candidate(BigDecimal device, int network, double dayFrequency,
                                        double hourFrequency, long subjectFailures, long ipFailures) {
        double history = Math.max(historyCandidate(subjectFailures, 3, 5), historyCandidate(ipFailures, 10, 20));
        return device.add(BigDecimal.valueOf(network))
                .add(BigDecimal.valueOf(temporalCandidate(dayFrequency, hourFrequency)))
                .add(BigDecimal.valueOf(history)).divide(new BigDecimal("4"), 2, RoundingMode.HALF_UP);
    }

    private static RiskDecision candidateDecision(BigDecimal score, boolean priority, boolean mandatory) {
        if (priority) return RiskDecision.DENY;
        if (score == null) return RiskDecision.STEP_UP_MFA;
        if (score.compareTo(new BigDecimal("75")) >= 0) return RiskDecision.DENY;
        if (mandatory || score.compareTo(new BigDecimal("40")) >= 0) return RiskDecision.STEP_UP_MFA;
        return RiskDecision.ALLOW;
    }
}
