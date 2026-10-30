package com.zerotrust.risk.audit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.risk.domain.*;
import com.zerotrust.risk.rule.*;
import com.zerotrust.risk.service.*;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/** Explicitly selected offline experiment, not part of the ordinary *Test[s] suite.
 * Requires controlled_study.py --generate. All I/O boundaries use read-only in-memory fixtures.
 * No Spring context, HTTP, database, Redis, credentials or Docker access.
 */
class ControlledStudyExperiment {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Path OUT = Path.of("target", "research", "controlled-v1");
    private static final String[] VARIANTS = {"B0", "TEMPORAL_ONLY", "HISTORY_ONLY", "B1"};
    private static volatile long blackhole;

    private static List<JsonNode> inputs() throws Exception {
        List<JsonNode> rows = new ArrayList<>();
        for (String line : Files.readAllLines(OUT.resolve("snapshots.jsonl"), StandardCharsets.UTF_8)) {
            rows.add(JSON.readTree(line));
        }
        assertThat(rows).hasSize(1008);
        assertThat(rows.stream().map(r -> r.path("case_id").asText()).distinct().count()).isEqualTo(rows.size());
        return rows;
    }

    private record Prepared(AuditRiskFixture fixture, RiskEvaluationService service,
                            AtomicReference<RiskFeatureExtraction> extraction,
                            AtomicReference<String> trace, LoginContext context,
                            TemporalRiskCalculator temporal, AuthenticationHistoryRiskCalculator history,
                            RiskScoringService scorer) {
        RiskEvaluation evaluate(JsonNode row) {
            return row.path("reset_pending").asBoolean() ? service.denyForPendingReset() : service.evaluate(context);
        }
    }

    private static Prepared prepare(JsonNode row, RiskScoreModel model) {
        AuditRiskFixture f = new AuditRiskFixture();
        f.policy.setModel(model);
        f.now = Instant.parse(row.path("now").asText());
        f.device = AuditRiskFixture.Device.valueOf(row.path("device").asText());
        f.trustedAt = f.now.minusSeconds(row.path("trusted_age_seconds").asLong());
        f.subjectFailures = row.path("subject_failures").asLong();
        f.ipFailures = row.path("ip_failures").asLong();
        f.failedCounter = row.path("failed_counter").asInt();
        f.temporalUnavailable = row.path("temporal_unavailable").asBoolean();
        f.network.setEnabled(row.path("network_enabled").asBoolean());
        f.ip = switch (row.path("network").asText()) {
            case "TRUSTED" -> "10.1.2.3";
            case "DEFAULT" -> "192.0.2.17";
            case "ELEVATED" -> "198.51.100.17";
            case "HIGH" -> "203.0.113.17";
            default -> throw new AssertionError("Unknown synthetic network context");
        };
        List<Instant> raw = new ArrayList<>();
        row.path("history").forEach(v -> raw.add(Instant.parse(v.asText())));
        // Mirror the declared JPA query boundary and Pageable cap, not an actual DB execution.
        f.history = raw.stream().filter(t -> !t.isBefore(f.now.minus(f.temporal.getHistoryWindow())) && t.isBefore(f.now))
                .sorted(Comparator.reverseOrder()).limit(f.temporal.getMaximumEvents()).toList();
        assertThat(f.history).hasSize(row.path("selected_n").asInt());
        assertThat(f.subjectFailures).isNotNegative();
        assertThat(f.ipFailures).isNotNegative();
        if (row.path("blocked_ip").asBoolean()) f.policy.getPriorityRules().setBlockedIpAddresses(List.of(f.ip));
        var rules = new PrioritySecurityRuleEvaluator(List.of(new BlockedIpPrioritySecurityRule(f.policy)));
        var extracted = new AtomicReference<RiskFeatureExtraction>();
        var trace = new AtomicReference<String>();
        var extractor = f.extractor();
        var service = new RiskEvaluationService(rules, context -> {
            var value = extractor.extract(context);
            extracted.set(value);
            return value;
        }, new RiskScoringService(f.policy), f.trace(trace::set));
        return new Prepared(f, service, extracted, trace, f.context(), f.temporalCalculator(), f.historyCalculator(), new RiskScoringService(f.policy));
    }

    private static Map<String, Object> result(JsonNode row, String variant, RiskEvaluation evaluation, String trace) throws Exception {
        JsonNode detail = JSON.readTree(trace);
        assertThat(detail.path("evaluation_id").asText()).isEqualTo(evaluation.evaluationId().toString());
        assertThat(UUID.fromString(detail.path("evaluation_id").asText())).isNotNull();
        assertThat(trace).doesNotContain("qa-subject", "qa-session", "qa-device", "10.1.2.3", "MFA_COMPLETED", "LOGIN_SUCCESS");
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("case_id", row.path("case_id").asText()); value.put("variant", variant);
        value.put("risk_score", evaluation.riskScore());
        value.put("trust_score", evaluation.riskScore() == null ? null : new BigDecimal("100").subtract(evaluation.riskScore()));
        value.put("decision", evaluation.decision().name()); value.put("data_status", evaluation.dataStatus().name());
        value.put("calculated_level", detail.get("calculated_level")); value.put("effective_level", evaluation.riskLevel().name());
        value.put("source", detail.path("decision_source").asText()); value.put("mandatory", detail.get("mandatory_step_up_present"));
        value.put("features", detail.get("features")); value.put("coverage", detail.get("coverage"));
        value.put("reason_codes", evaluation.reasons().stream().map(Enum::name).toList());
        assertInvariant(evaluation, detail);
        return value;
    }

    private static void assertInvariant(RiskEvaluation result, JsonNode detail) {
        if (result.dataStatus() == RiskDataStatus.NOT_EVALUATED) {
            assertThat(result.decision()).isEqualTo(RiskDecision.DENY); assertThat(result.riskScore()).isNull();
        } else if (result.dataStatus() == RiskDataStatus.INCOMPLETE) {
            assertThat(result.decision()).isEqualTo(RiskDecision.STEP_UP_MFA); assertThat(result.riskScore()).isNull();
            assertThat(detail.get("trust_score").isNull()).isTrue();
        } else {
            assertThat(result.riskScore()).isBetween(BigDecimal.ZERO, new BigDecimal("100"));
            if (result.riskScore().compareTo(new BigDecimal("75")) >= 0) assertThat(result.decision()).isEqualTo(RiskDecision.DENY);
            if (detail.path("mandatory_step_up_present").asBoolean()) assertThat(result.decision()).isNotEqualTo(RiskDecision.ALLOW);
        }
    }

    @Test
    void pairedSnapshotsAndRealComponentAblations() throws Exception {
        List<String> output = new ArrayList<>();
        Set<UUID> ids = new HashSet<>();
        for (JsonNode row : inputs()) {
            Prepared b0 = prepare(row, RiskScoreModel.BASELINE_B0), b1 = prepare(row, RiskScoreModel.CONTINUOUS_B1);
            RiskEvaluation e0 = b0.evaluate(row), e1 = b1.evaluate(row);
            String trace0 = b0.trace.get(), trace1 = b1.trace.get();
            for (var pair : List.of(Map.entry(b0, e0), Map.entry(b1, e1))) {
                assertThat(ids.add(pair.getValue().evaluationId())).isTrue();
                var again = pair.getKey().evaluate(row);
                assertThat(again.riskScore()).isEqualTo(pair.getValue().riskScore());
                assertThat(again.decision()).isEqualTo(pair.getValue().decision());
                assertThat(again.dataStatus()).isEqualTo(pair.getValue().dataStatus());
            }
            output.add(JSON.writeValueAsString(result(row, "B0", e0, trace0)));
            output.add(JSON.writeValueAsString(result(row, "B1", e1, trace1)));
            for (String variant : List.of("TEMPORAL_ONLY", "HISTORY_ONLY")) {
                var x0 = b0.extraction.get(); var x1 = b1.extraction.get();
                var hybrid = x0 == null ? null : new RiskFeatureExtraction(new RiskFactors(
                        x0.factors().deviceRisk(), x0.factors().networkRisk(),
                        variant.equals("TEMPORAL_ONLY") ? x1.factors().temporalRisk() : x0.factors().temporalRisk(),
                        variant.equals("HISTORY_ONLY") ? x1.factors().authenticationHistoryRisk() : x0.factors().authenticationHistoryRisk()),
                        x0.dataStatus(), x0.reasons(), x0.priorityViolation(), x0.mandatoryStepUpReason(), x0.evidence());
                AtomicReference<String> trace = new AtomicReference<>();
                var service = new RiskEvaluationService(new PrioritySecurityRuleEvaluator(List.of(new BlockedIpPrioritySecurityRule(b0.fixture.policy))),
                        context -> Objects.requireNonNull(hybrid), new RiskScoringService(b0.fixture.policy), b0.fixture.trace(trace::set));
                var evaluation = row.path("reset_pending").asBoolean() ? service.denyForPendingReset() : service.evaluate(b0.fixture.context());
                // These are offline hybrid ablations, not new supported production model identifiers.
                output.add(JSON.writeValueAsString(result(row, variant, evaluation, trace.get())));
            }
        }
        assertThat(output).hasSize(4032);
        writeOnce(OUT.resolve("java-results.jsonl"), String.join("\n", output)+"\n");
    }

    @Test
    void roundingBoundaryContract() throws Exception {
        List<Map<String, Object>> rows = new ArrayList<>();
        var service = new RiskScoringService(AuditRiskFixture.policy(".25", ".25", ".25", ".25"));
        for (String value : List.of("39.994", "39.995", "39.99", "40.00", "74.994", "74.995", "74.99", "75.00")) {
            BigDecimal x = new BigDecimal(value);
            var result = service.evaluate(new RiskFactors(x, x, x, x));
            rows.add(Map.of("input_each_feature", value, "score", result.riskScore(), "decision", result.decision().name(),
                    "kind", "ARITHMETIC_CONTRACT_NOT_EXTRACTED_CONTEXT_OR_QUALITY_LABEL"));
        }
        writeOnce(OUT.resolve("rounding-boundaries.json"), JSON.writerWithDefaultPrettyPrinter().writeValueAsString(rows)+"\n");
    }

    @Test
    void boundedBenchmark() throws Exception {
        int fork = Integer.parseInt(Objects.requireNonNull(System.getProperty("research.fork"), "Select benchmark explicitly with -Dresearch.fork=1..3"));
        assertThat(fork).isBetween(1, 3);
        Path target = OUT.resolve("benchmark-fork-"+fork+".json");
        assertThat(Files.exists(target)).isFalse();
        List<JsonNode> eligible = inputs().stream().filter(r -> r.path("selected_n").asInt() >= 5
                && r.path("network_enabled").asBoolean() && r.path("failed_counter").asInt() == 0
                && !r.path("temporal_unavailable").asBoolean() && !r.path("blocked_ip").asBoolean()
                && !r.path("reset_pending").asBoolean() && !r.path("device").asText().equals("SECURITY_REVOKED")).toList();
        List<JsonNode> chosen = new ArrayList<>();
        for (int n : new int[]{5, 10, 20, 50, 199, 200}) {
            List<JsonNode> sameSize = eligible.stream().filter(r -> r.path("selected_n").asInt() == n).toList();
            for (int j = 0; j < 4; j++) chosen.add(sameSize.get(j * sameSize.size()/4));
        }
        List<Prepared> b0 = chosen.stream().map(r -> prepare(r, RiskScoreModel.BASELINE_B0)).toList();
        List<Prepared> b1 = chosen.stream().map(r -> prepare(r, RiskScoreModel.CONTINUOUS_B1)).toList();
        var random = new Random(20261030L+fork);
        List<Map<String, Object>> samples = new ArrayList<>();
        for (String scope : List.of("TEMPORAL_HISTORY_SCORER_NO_IO", "IN_MEMORY_PIPELINE_WITH_TRACE_SERIALIZATION_NO_LOG_IO")) {
            for (int i = 0; i < 6000; i++) {
                int index = i % chosen.size();
                consume(timedOperation(b0.get(index), chosen.get(index), scope));
                consume(timedOperation(b1.get(index), chosen.get(index), scope));
            }
            for (int batch = 0; batch < 24; batch++) {
                boolean firstB1 = random.nextBoolean();
                for (int order = 0; order < 2; order++) {
                    boolean isB1 = firstB1 == (order == 0);
                    List<Prepared> prepared = isB1 ? b1 : b0;
                    List<Long> nanos = new ArrayList<>();
                    long batchStart = System.nanoTime();
                    for (int i = 0; i < chosen.size(); i++) {
                        long started = System.nanoTime();
                        var result = timedOperation(prepared.get(i), chosen.get(i), scope);
                        nanos.add(System.nanoTime()-started); consume(result);
                    }
                    samples.add(Map.of("scope", scope, "model", isB1 ? "B1" : "B0", "batch", batch,
                            "per_operation_ns", nanos, "batch_elapsed_ns", System.nanoTime()-batchStart));
                }
            }
        }
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("fork", fork); metadata.put("kind", "LOCAL_OFFLINE_MICROBENCHMARK_NOT_HTTP_OR_BROWSER_LATENCY");
        metadata.put("java_version", System.getProperty("java.version")); metadata.put("vm", System.getProperty("java.vm.name"));
        metadata.put("os", System.getProperty("os.name")); metadata.put("arch", System.getProperty("os.arch"));
        metadata.put("processors", Runtime.getRuntime().availableProcessors()); metadata.put("max_heap_bytes", Runtime.getRuntime().maxMemory());
        metadata.put("warmup_per_model_per_scope", 6000); metadata.put("batches_per_model_per_scope", 24);
        metadata.put("operations_per_batch", chosen.size()); metadata.put("case_ids", chosen.stream().map(r -> r.path("case_id").asText()).toList());
        metadata.put("samples", samples);
        writeOnce(target, JSON.writerWithDefaultPrettyPrinter().writeValueAsString(metadata)+"\n");
    }

    private static RiskEvaluation timedOperation(Prepared p, JsonNode row, String scope) {
        if (scope.startsWith("IN_MEMORY")) return p.evaluate(row);
        var t = p.temporal.calculate(p.context);
        var h = p.history.calculate(p.context).orElseThrow();
        return p.scorer.evaluate(new RiskFactors(BigDecimal.ZERO, new BigDecimal("50"), t.riskScore(), h.riskScore()));
    }

    private static void consume(RiskEvaluation value) {
        blackhole += value.decision().ordinal() + (value.riskScore() == null ? 0 : value.riskScore().longValue());
    }

    private static void writeOnce(Path path, String contents) throws Exception {
        if (Files.exists(path)) assertThat(Files.readString(path, StandardCharsets.UTF_8)).isEqualTo(contents);
        else Files.writeString(path, contents, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
    }
}
