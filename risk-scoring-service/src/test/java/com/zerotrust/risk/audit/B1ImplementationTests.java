package com.zerotrust.risk.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.risk.config.RiskPolicyProperties;
import com.zerotrust.risk.domain.*;
import com.zerotrust.risk.rule.PrioritySecurityRuleEvaluator;
import com.zerotrust.risk.service.*;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import java.math.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.*;

/** Actual B0/B1 component integration with in-memory I/O; never a Browser acceptance test. */
class B1ImplementationTests {
    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void b1RequiresAnExplicitValidModelSelection() {
        assertThat(new RiskPolicyProperties().getModel()).isEqualTo(RiskScoreModel.BASELINE_B0);
        Binder binder = new Binder(new MapConfigurationPropertySource(Map.of("risk.policy.model", "CONTINUOUS_B1")));
        assertThat(binder.bind("risk.policy", Bindable.of(RiskPolicyProperties.class)).get().getModel())
                .isEqualTo(RiskScoreModel.CONTINUOUS_B1);
        assertThatThrownBy(() -> new Binder(new MapConfigurationPropertySource(Map.of(
                "risk.policy.model", "UNKNOWN_MODEL"))).bind("risk.policy", Bindable.of(RiskPolicyProperties.class)))
                .isInstanceOf(org.springframework.boot.context.properties.bind.BindException.class);
    }

    @Test
    void normalizersUseDecimalAnchorsAndRejectInvalidInputs() {
        long[] counts = {0, 1, 2, 3, 4, 5, 6};
        String[] values = {"0", "16.66666666666666666666666666666667", "33.33333333333333333333333333333333", "50", "75", "100", "100"};
        for (int i = 0; i < counts.length; i++) {
            assertThat(BehavioralRiskNormalizer.failureRisk(counts[i], 3, 5)).isEqualByComparingTo(values[i]);
        }
        assertThat(BehavioralRiskNormalizer.failureRisk(19, 10, 20)).isEqualByComparingTo("95");
        assertThat(BehavioralRiskNormalizer.temporalRisk(2, 3, 20, bd(".1"), bd(".2")))
                .isEqualByComparingTo("12.5");
        assertThat(BehavioralRiskNormalizer.temporalRisk(2, 4, 20, bd(".1"), bd(".2"))).isZero();
        assertThatThrownBy(() -> BehavioralRiskNormalizer.failureRisk(-1, 3, 5)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> BehavioralRiskNormalizer.failureRisk(1, 0, 5)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> BehavioralRiskNormalizer.failureRisk(1, 5, 5)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> BehavioralRiskNormalizer.temporalRisk(0, 0, 0, bd(".1"), bd(".2")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> BehavioralRiskNormalizer.temporalRisk(21, 0, 20, bd(".1"), bd(".2")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> BehavioralRiskNormalizer.temporalRisk(0, 0, 20, BigDecimal.ZERO, bd(".2")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void normalizersAreBoundedAndMonotoneAcrossCounterAndFrequencyDomains() {
        BigDecimal previous = BigDecimal.ZERO;
        for (int count = 0; count <= 100; count++) {
            BigDecimal value = BehavioralRiskNormalizer.failureRisk(count, 3, 5);
            assertThat(value).isBetween(BigDecimal.ZERO, bd("100")).isGreaterThanOrEqualTo(previous);
            previous = value;
        }
        for (int day = 0; day <= 200; day++) {
            BigDecimal previousHour = bd("100");
            for (int hour = 0; hour <= 200; hour++) {
                BigDecimal value = BehavioralRiskNormalizer.temporalRisk(day, hour, 200, bd(".1"), bd(".2"));
                assertThat(value).isBetween(BigDecimal.ZERO, bd("100")).isLessThanOrEqualTo(previousHour);
                if (day > 0) assertThat(value).isLessThanOrEqualTo(
                        BehavioralRiskNormalizer.temporalRisk(day - 1, hour, 200, bd(".1"), bd(".2")));
                previousHour = value;
            }
        }
    }

    @Test
    void realModelsMatchExactRationalOracleAndExportPairedReplay() throws Exception {
        List<String> csv = new ArrayList<>(List.of("kind,events,device,network,day_matches,hour_matches,subject_failures,b0_score,b1_score,b0_decision,b1_decision"));
        Map<String, Integer> b0Actions = new TreeMap<>(), b1Actions = new TreeMap<>(), transitions = new TreeMap<>();
        int count = 0;
        for (int size : new int[]{10, 20, 50, 199, 200}) {
            for (var device : List.of(AuditRiskFixture.Device.TRUSTED, AuditRiskFixture.Device.MISSING)) {
                for (int network : new int[]{0, 50, 100}) {
                    for (int days : new int[]{0, 1, 2, size / 2, size}) {
                        for (int hours : new int[]{0, 1, 3, size / 2, size}) {
                            for (int failures = 0; failures <= 5; failures++) {
                                AuditRiskFixture f = fixture(RiskScoreModel.BASELINE_B0, device, network, size, days, hours, failures);
                                RiskEvaluation b0 = f.evaluate();
                                int baselineTime = (days * 10 < size ? 50 : 0) + (hours * 5 < size ? 50 : 0);
                                int baselineHistory = failures >= 5 ? 100 : failures >= 3 ? 50 : 0;
                                assertThat(b0.riskScore()).isEqualByComparingTo(bd("" + (
                                        (device == AuditRiskFixture.Device.MISSING ? 80 : 0) + network + baselineTime + baselineHistory))
                                        .divide(bd("4"), 2, RoundingMode.HALF_UP));
                                f.policy.setModel(RiskScoreModel.CONTINUOUS_B1);
                                RiskEvaluation b1 = f.evaluate();
                                Fraction temporal = Fraction.of(Math.max(0, size - 10L * days), size)
                                        .add(Fraction.of(Math.max(0, size - 5L * hours), size)).multiply(50);
                                Fraction history = failures <= 3 ? Fraction.of(50L * failures, 3)
                                        : Fraction.of(50L + 25L * Math.min(failures - 3, 2), 1);
                                BigDecimal exact = Fraction.of((device == AuditRiskFixture.Device.MISSING ? 80 : 0) + network, 1)
                                        .add(temporal).add(history).divide(4).cents();
                                assertThat(b1.riskScore()).as("n=%s,d=%s,h=%s,fail=%s", size, days, hours, failures)
                                        .isEqualByComparingTo(exact);
                                boolean mandatory = device == AuditRiskFixture.Device.MISSING || network == 100 || failures >= 5;
                                RiskDecision expected = exact.compareTo(bd("75")) >= 0 ? RiskDecision.DENY
                                        : mandatory || exact.compareTo(bd("40")) >= 0 ? RiskDecision.STEP_UP_MFA : RiskDecision.ALLOW;
                                assertThat(b1.decision()).isEqualTo(expected);
                                assertThat(b1.dataStatus()).isEqualTo(RiskDataStatus.COMPLETE);
                                b0Actions.merge(b0.decision().name(), 1, Integer::sum);
                                b1Actions.merge(b1.decision().name(), 1, Integer::sum);
                                if (b0.decision() != b1.decision()) transitions.merge(
                                        b0.decision() + "->" + b1.decision(), 1, Integer::sum);
                                csv.add(String.join(",", "SYNTHETIC_OFFLINE", "" + size, device.name(), "" + network,
                                        "" + days, "" + hours, "" + failures, b0.riskScore().toPlainString(),
                                        b1.riskScore().toPlainString(), b0.decision().name(), b1.decision().name()));
                                count++;
                            }
                        }
                    }
                }
            }
        }
        assertThat(count).isEqualTo(4500);
        Path out = Path.of("target", "research", "b1-implementation");
        Files.createDirectories(out);
        Files.write(out.resolve("paired-replay.csv"), csv, StandardCharsets.UTF_8);
        JSON.writerWithDefaultPrettyPrinter().writeValue(out.resolve("paired-summary.json").toFile(), Map.of(
                "kind", "SYNTHETIC_CONTROLLED_COMPONENT_INTEGRATION", "pairs", count,
                "baseline_actions", b0Actions, "b1_actions", b1Actions, "transitions", transitions,
                "b1_oracle", "EXACT_BIG_INTEGER_FRACTIONS_FINAL_HALF_UP"));
    }

    @Test
    void a5AndA6RemainNumericDecisionsUnderB1() {
        AuditRiskFixture a5 = fixture(RiskScoreModel.CONTINUOUS_B1, AuditRiskFixture.Device.TRUSTED, 50, 20, 0, 0, 3);
        assertThat(a5.extractor().extract(a5.context()).mandatoryStepUpReason()).isEmpty();
        assertThat(a5.evaluate().riskScore()).isEqualByComparingTo("50");
        assertThat(a5.evaluate().decision()).isEqualTo(RiskDecision.STEP_UP_MFA);
        AuditRiskFixture a6 = fixture(RiskScoreModel.CONTINUOUS_B1, AuditRiskFixture.Device.TRUSTED, 100, 20, 0, 0, 5);
        assertThat(a6.extractor().extract(a6.context()).priorityViolation()).isEmpty();
        assertThat(a6.evaluate().riskScore()).isEqualByComparingTo("75");
        assertThat(a6.evaluate().decision()).isEqualTo(RiskDecision.DENY);
    }

    @Test
    void missingnessAndSecurityRevocationKeepTheirPolicyInBothModels() {
        for (var model : RiskScoreModel.values()) for (int mask = 1; mask <= 7; mask++) {
            AuditRiskFixture f = fixture(model, AuditRiskFixture.Device.TRUSTED, 100, 20, 0, 0, 5);
            f.failedCounter = (mask & 1) != 0 ? 1 : 0;
            f.network.setEnabled((mask & 2) == 0);
            f.temporalUnavailable = (mask & 4) != 0;
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
    void coldStartTraceHasNullPointScoreAndNoOptimisticCoverage() throws Exception {
        AuditRiskFixture f = fixture(RiskScoreModel.CONTINUOUS_B1, AuditRiskFixture.Device.TRUSTED, 0, 4, 4, 4, 0);
        List<String> lines = new ArrayList<>();
        var result = evaluate(f, lines::add);
        var row = JSON.readTree(lines.get(0));
        assertThat(result.decision()).isEqualTo(RiskDecision.STEP_UP_MFA);
        assertThat(row.get("risk_score").isNull()).isTrue();
        assertThat(row.get("trust_score").isNull()).isTrue();
        assertThat(row.get("calculated_level").isNull()).isTrue();
        assertThat(row.get("coverage").decimalValue()).isEqualByComparingTo(".75");
        assertThat(row.at("/features/temporal/status").asText()).isEqualTo("COLD_START");
        assertThat(row.at("/features/temporal/score").isNull()).isTrue();
        assertThat(row.at("/features/temporal/contribution").isNull()).isTrue();
        assertThat(row.at("/risk_interval/1").decimalValue()).isEqualByComparingTo("25");
        assertThat(row.at("/trust_interval/0").decimalValue()).isEqualByComparingTo("75");
        assertThat(row.get("decision_source").asText()).isEqualTo("INCOMPLETE_DATA");
    }

    @Test
    void traceCorrelatesContributionsAndDistinguishesNumericFromEffectiveLevel() throws Exception {
        AuditRiskFixture f = fixture(RiskScoreModel.CONTINUOUS_B1, AuditRiskFixture.Device.MISSING, 0, 20, 20, 20, 0);
        List<String> lines = new ArrayList<>();
        var result = evaluate(f, lines::add);
        var row = JSON.readTree(lines.get(0));
        assertThat(row.get("evaluation_id").asText()).isEqualTo(result.evaluationId().toString());
        assertThat(row.get("model_version").asText()).isEqualTo("CONTINUOUS_B1:1");
        assertThat(row.get("calculated_level").asText()).isEqualTo("LOW");
        assertThat(row.get("effective_level").asText()).isEqualTo("MEDIUM");
        assertThat(row.get("trust_score").decimalValue()).isEqualByComparingTo("80");
        assertThat(row.get("decision_source").asText()).isEqualTo("MANDATORY_STEP_UP");
        assertThat(row.at("/features/device/status").asText()).isEqualTo("AVAILABLE");
        assertThat(row.at("/features/device/source").asText()).isEqualTo("MISSING");
        assertThat(row.get("risk_pipeline_duration_ms").decimalValue()).isNotNegative();
        BigDecimal contributions = BigDecimal.ZERO;
        for (var feature : row.get("features")) contributions = contributions.add(feature.get("contribution").decimalValue());
        assertThat(contributions.setScale(2, RoundingMode.HALF_UP)).isEqualByComparingTo(result.riskScore());
        assertThat(row.get("numeric_config_digest").asText()).matches("[0-9a-f]{64}");
        f.policy.setModel(RiskScoreModel.BASELINE_B0);
        evaluate(f, lines::add);
        assertThat(JSON.readTree(lines.get(1)).get("numeric_config_digest").asText())
                .isNotEqualTo(row.get("numeric_config_digest").asText());
        assertThat(String.join("", lines)).doesNotContain("qa-subject", "qa-session", "qa-device", "10.1.2.3",
                "MFA_COMPLETED", "LOGIN_SUCCESS", "fingerprint", "pepper", "userAgent", "cookie");
    }

    @Test
    void priorityAndPendingResetTraceNeverInventNumericScores() throws Exception {
        AuditRiskFixture f = fixture(RiskScoreModel.CONTINUOUS_B1, AuditRiskFixture.Device.SECURITY_REVOKED, 0, 20, 20, 20, 0);
        List<String> lines = new ArrayList<>();
        evaluate(f, lines::add);
        var service = service(f, lines::add);
        var reset = service.denyForPendingReset();
        assertThat(reset.decision()).isEqualTo(RiskDecision.DENY);
        assertThat(reset.reasons()).containsExactly(RiskReason.MFA_RESET_IN_PROGRESS);
        for (String line : lines) {
            var row = JSON.readTree(line);
            assertThat(row.get("decision_source").asText()).isEqualTo("PRIORITY_RULE");
            for (String field : List.of("risk_score", "trust_score", "calculated_level", "coverage", "features", "trust_interval"))
                assertThat(row.get(field).isNull()).as(field).isTrue();
        }
    }

    @Test
    void loggerFailureCannotChangeAllowMfaOrDeny() {
        for (var device : List.of(AuditRiskFixture.Device.TRUSTED, AuditRiskFixture.Device.MISSING, AuditRiskFixture.Device.SECURITY_REVOKED)) {
            AuditRiskFixture f = fixture(RiskScoreModel.CONTINUOUS_B1, device, 0, 20, 20, 20, 0);
            var expected = f.evaluate();
            var result = evaluate(f, line -> { throw new IllegalStateException("sensitive-context-canary"); });
            assertThat(result.decision()).isEqualTo(expected.decision());
            assertThat(result.riskScore()).isEqualTo(expected.riskScore());
            assertThat(result.dataStatus()).isEqualTo(expected.dataStatus());
        }
    }

    private static AuditRiskFixture fixture(RiskScoreModel model, AuditRiskFixture.Device device, int network,
                                            int size, int days, int hours, int failures) {
        AuditRiskFixture f = new AuditRiskFixture();
        f.policy.setModel(model); f.device = device; f.subjectFailures = failures;
        f.ip = network == 0 ? "10.1.2.3" : network == 50 ? "198.51.100.17" : "203.0.113.17";
        List<java.time.Instant> events = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            var time = AuditRiskFixture.NOW.minusSeconds(7L * (i % 10 + 1) * 86400).minusSeconds(i / 10 * 60L);
            if (i >= days) time = time.plusSeconds(86400);
            if (i >= hours) time = time.plusSeconds(6 * 3600);
            events.add(time);
        }
        f.history = events;
        return f;
    }

    @Test
    void numericHighTraceIsScoreDrivenDespiteTheMandatorySignals() throws Exception {
        for (int failures : new int[]{0, 5}) {
            AuditRiskFixture f = fixture(RiskScoreModel.CONTINUOUS_B1, AuditRiskFixture.Device.TRUSTED, 100, 20, 0, 0, failures);
            List<String> lines = new ArrayList<>();
            evaluate(f, lines::add);
            var row = JSON.readTree(lines.get(0));
            assertThat(row.get("risk_score").decimalValue()).isEqualByComparingTo(failures == 0 ? "50" : "75");
            assertThat(row.get("trust_score").decimalValue()).isEqualByComparingTo(failures == 0 ? "50" : "25");
            assertThat(row.get("calculated_level").asText()).isEqualTo(failures == 0 ? "MEDIUM" : "HIGH");
            assertThat(row.get("effective_level").asText()).isEqualTo(failures == 0 ? "MEDIUM" : "HIGH");
            assertThat(row.get("mandatory_step_up_present").asBoolean()).isTrue();
            // Both guards can apply; the score already suffices for MEDIUM/HIGH.
            assertThat(row.get("decision_source").asText()).isEqualTo("SCORE_THRESHOLD");
        }
    }

    @Test
    void missingFeatureIntervalsContainQuantizedScoresWithoutRenormalizingWeights() throws Exception {
        AuditRiskFixture f = fixture(RiskScoreModel.CONTINUOUS_B1, AuditRiskFixture.Device.TRUSTED, 0, 20, 20, 20, 1);
        f.network.setEnabled(false); f.temporalUnavailable = true;
        List<String> lines = new ArrayList<>();
        evaluate(f, lines::add);
        var row = JSON.readTree(lines.get(0));
        assertThat(row.get("coverage").decimalValue()).isEqualByComparingTo(".5");
        assertThat(row.at("/risk_interval/0").decimalValue()).isEqualByComparingTo("4.17");
        assertThat(row.at("/risk_interval/1").decimalValue()).isEqualByComparingTo("54.17");
        assertThat(row.at("/trust_interval/0").decimalValue()).isEqualByComparingTo("45.83");
        assertThat(row.get("trust_score").isNull()).isTrue();
        assertThat(row.at("/features/network/contribution").isNull()).isTrue();
    }

    @Test
    void extractorWithoutEvidenceCannotClaimCompleteObservedCoverage() throws Exception {
        AuditRiskFixture f = fixture(RiskScoreModel.CONTINUOUS_B1, AuditRiskFixture.Device.TRUSTED, 0, 20, 20, 20, 0);
        List<String> lines = new ArrayList<>();
        var service = new RiskEvaluationService(new PrioritySecurityRuleEvaluator(List.of()),
                ignored -> new RiskFeatureExtraction(new RiskFactors(BigDecimal.ZERO, BigDecimal.ZERO,
                        BigDecimal.ZERO, BigDecimal.ZERO), RiskDataStatus.COMPLETE, List.of()),
                new RiskScoringService(f.policy), f.trace(lines::add));
        assertThat(service.evaluate(f.context()).decision()).isEqualTo(RiskDecision.ALLOW);
        assertThat(JSON.readTree(lines.get(0)).get("coverage").isNull()).isTrue();
    }

    private static RiskEvaluation evaluate(AuditRiskFixture f, Consumer<String> sink) {
        return service(f, sink).evaluate(f.context());
    }
    private static RiskEvaluationService service(AuditRiskFixture f, Consumer<String> sink) {
        return new RiskEvaluationService(new PrioritySecurityRuleEvaluator(List.of()), f.extractor(),
                new RiskScoringService(f.policy), f.trace(sink));
    }
    private static BigDecimal bd(String value) { return new BigDecimal(value); }

    // Independent exact rational oracle. No BigDecimal division/production normalization used.
    private record Fraction(BigInteger numerator, BigInteger denominator) {
        static Fraction of(long n, long d) { return new Fraction(BigInteger.valueOf(n), BigInteger.valueOf(d)); }
        Fraction add(Fraction other) { return new Fraction(numerator.multiply(other.denominator).add(other.numerator.multiply(denominator)), denominator.multiply(other.denominator)); }
        Fraction multiply(long n) { return new Fraction(numerator.multiply(BigInteger.valueOf(n)), denominator); }
        Fraction divide(long n) { return new Fraction(numerator, denominator.multiply(BigInteger.valueOf(n))); }
        BigDecimal cents() {
            BigInteger[] qr = numerator.multiply(BigInteger.valueOf(100)).divideAndRemainder(denominator);
            return new BigDecimal(qr[0].add(qr[1].shiftLeft(1).compareTo(denominator) >= 0 ? BigInteger.ONE : BigInteger.ZERO), 2);
        }
    }
}
