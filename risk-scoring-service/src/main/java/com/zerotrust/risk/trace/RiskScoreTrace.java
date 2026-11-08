package com.zerotrust.risk.trace;

import tools.jackson.databind.ObjectMapper;
import com.zerotrust.risk.config.*;
import com.zerotrust.risk.domain.*;
import org.jboss.logging.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

/** Best-effort structured explanation, joined to the existing SPI trace by evaluation_id.
 * Never accepts LoginContext, identifiers, secrets, raw network policy or HTTP payloads.
 */
@Component
public class RiskScoreTrace {
    private static final Logger LOG = Logger.getLogger(RiskScoreTrace.class);
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final BigDecimal HUNDRED = new BigDecimal("100");
    private final RiskPolicyProperties policy;
    private final DeviceRiskProperties device;
    private final NetworkRiskProperties network;
    private final TemporalRiskProperties temporal;
    private final AuthenticationHistoryRiskProperties history;
    private final Consumer<String> sink;

    @Autowired
    public RiskScoreTrace(RiskPolicyProperties policy, DeviceRiskProperties device,
                          NetworkRiskProperties network, TemporalRiskProperties temporal,
                          AuthenticationHistoryRiskProperties history) {
        this(policy, device, network, temporal, history,
                line -> LOG.info("ZEROTRUST_RISK_SCORE_TRACE " + line));
    }

    public RiskScoreTrace(RiskPolicyProperties policy, DeviceRiskProperties device,
                          NetworkRiskProperties network, TemporalRiskProperties temporal,
                          AuthenticationHistoryRiskProperties history, Consumer<String> sink) {
        this.policy = Objects.requireNonNull(policy);
        this.device = Objects.requireNonNull(device);
        this.network = Objects.requireNonNull(network);
        this.temporal = Objects.requireNonNull(temporal);
        this.history = Objects.requireNonNull(history);
        this.sink = Objects.requireNonNull(sink);
    }

    public void record(RiskEvaluation evaluation, RiskFeatureExtraction extraction, long durationNanos) {
        try {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("schema_version", 2);
            row.put("stage", "RISK_EVALUATION_DETAILS");
            row.put("at", Instant.now().toString());
            row.put("evaluation_id", evaluation.evaluationId().toString());
            row.put("model_version", policy.getModel().name() + ":1");
            row.put("numeric_config_digest", numericConfigDigest());
            row.put("policy_thresholds", Map.of("medium_minimum", policy.getThresholds().getMediumMinimum(),
                    "high_minimum", policy.getThresholds().getHighMinimum()));
            row.put("user_agent_used_for_scoring", false);
            row.put("risk_pipeline_duration_ms", BigDecimal.valueOf(Math.max(0, durationNanos), 6));
            row.put("risk_score", evaluation.riskScore());
            row.put("trust_score", evaluation.riskScore() == null ? null : HUNDRED.subtract(evaluation.riskScore()));
            RiskLevel calculated = calculatedLevel(evaluation.riskScore());
            row.put("calculated_level", calculated == null ? null : calculated.name());
            row.put("effective_level", evaluation.riskLevel().name());
            row.put("decision", evaluation.decision().name());
            row.put("data_status", evaluation.dataStatus().name());
            boolean mandatory = extraction != null && extraction.mandatoryStepUpReason().isPresent();
            row.put("mandatory_step_up_present", extraction == null ? null : mandatory);
            row.put("mandatory_step_up_reason", extraction == null ? null
                    : extraction.mandatoryStepUpReason().map(Enum::name).orElse(null));
            row.put("decision_source", evaluation.dataStatus() == RiskDataStatus.NOT_EVALUATED ? "PRIORITY_RULE"
                    : evaluation.dataStatus() == RiskDataStatus.INCOMPLETE ? "INCOMPLETE_DATA"
                    : calculated != RiskLevel.LOW || !mandatory ? "SCORE_THRESHOLD" : "MANDATORY_STEP_UP");
            row.put("reason_codes", evaluation.reasons().stream().map(Enum::name).toList());
            // Priority exits did not produce a weighted score. Do not fabricate its components/bounds.
            addFeatures(row, evaluation.dataStatus() == RiskDataStatus.NOT_EVALUATED ? null : extraction);
            sink.accept(JSON.writeValueAsString(row));
        } catch (Exception | LinkageError ignored) {
            // Explanation/serialization/logger failure must not change DENY, MFA or ALLOW.
            // Exception messages can contain context: never emit them here.
        }
    }

    private void addFeatures(Map<String, Object> row, RiskFeatureExtraction extraction) {
        row.put("features", null);
        row.put("coverage", null);
        row.put("risk_interval", null);
        row.put("trust_interval", null);
        if (extraction == null) return;
        RiskFeatureEvidence e = extraction.evidence();
        RiskFactors factors = extraction.factors();
        var w = policy.getWeights();
        Map<String, Map<String, Object>> features = new LinkedHashMap<>();
        features.put("device", feature(e.device(), factors.deviceRisk(), w.getDevice(), e.deviceState()));
        features.put("network", feature(e.network(), factors.networkRisk(), w.getNetwork(), e.networkSource()));
        features.put("temporal", feature(e.temporal(), factors.temporalRisk(), w.getTemporal(), null));
        features.put("authentication_history", feature(e.authenticationHistory(), factors.authenticationHistoryRisk(),
                w.getAuthenticationHistory(), null));
        addInputs(features, e.signals());
        row.put("features", features);
        // Older/custom extractors with no evidence cannot claim measured coverage.
        if (features.values().stream().anyMatch(f -> "NOT_OBSERVED".equals(f.get("status")))) return;
        BigDecimal coverage = BigDecimal.ZERO, lower = BigDecimal.ZERO;
        for (var feature : features.values()) {
            if (feature.get("contribution") != null) {
                coverage = coverage.add((BigDecimal) feature.get("weight"));
                lower = lower.add((BigDecimal) feature.get("contribution"));
            }
        }
        BigDecimal upper = lower.add(BigDecimal.ONE.subtract(coverage).multiply(HUNDRED));
        row.put("coverage", coverage);
        if (extraction.dataStatus() == RiskDataStatus.INCOMPLETE) {
            // Bound the reported (quantized) score, not an unrounded number that could
            // exclude a valid score by a fraction of a cent. HALF_UP is monotone here.
            lower = lower.setScale(2, RoundingMode.HALF_UP);
            upper = upper.setScale(2, RoundingMode.HALF_UP);
            row.put("risk_interval", List.of(lower, upper));
            row.put("trust_interval", List.of(HUNDRED.subtract(upper), HUNDRED.subtract(lower)));
        }
    }

    private void addInputs(Map<String, Map<String, Object>> features, RiskSignalSnapshot signals) {
        features.values().forEach(feature -> feature.put("inputs", null));
        if (signals == null) return;
        features.get("device").put("inputs", fields("recognition_reason", name(signals.deviceReason()),
                "recognition_source", "DEVICE_COOKIE_AND_SERVER_RECORD"));
        NetworkRiskAssessment n = signals.network();
        if (n != null) {
            GeoIpLocation location = n.geoIpLocation();
            var observation = n.observation();
            features.get("network").put("inputs", fields(
                    "ip_source", "RISK_REQUEST_IP_ADDRESS",
                    "address_scope", observation == null ? null : name(observation.addressScope()),
                    "geoip_status", observation == null ? null : name(observation.geoIpUse()),
                    "policy_band", name(n.band()), "unavailable_reason", name(n.unavailableReason()),
                    "country_code", location == null ? null : location.countryCode(),
                    "city_name", location == null ? null : safeText(location.cityName()),
                    "geoip_time_zone", location == null ? null : safeText(location.timeZone()),
                    "accuracy_radius_km", location == null ? null : location.accuracyRadiusKm(),
                    "asn", location == null ? null : location.autonomousSystemNumber(),
                    "asn_organization", location == null ? null : safeText(location.autonomousSystemOrganization()),
                    "geoip_scoring_field", n.usesGeoIp() ? "COUNTRY_CODE" : null));
        }
        var t = signals.temporal();
        if (t != null) {
            features.get("temporal").put("inputs", fields("history_source", "SUCCESS_EVENTS_MYSQL",
                    "evaluated_at", t.evaluatedAt().toString(), "zone_id", t.zoneId(),
                    "history_window_seconds", t.historyWindowSeconds(), "minimum_events", t.minimumEvents(),
                    "maximum_events", t.maximumEvents(), "sample_size", t.sampleSize(),
                    "day_of_week", t.dayOfWeek(), "hour", t.hour(), "hour_tolerance", t.hourTolerance(),
                    "matching_days", t.matchingDays(), "matching_hours", t.matchingHours(),
                    "minimum_day_frequency", t.minimumDayFrequency(),
                    "minimum_hour_frequency", t.minimumHourFrequency()));
        }
        var h = signals.authenticationHistory();
        if (h != null) {
            features.get("authentication_history").put("inputs", fields("history_source", "FAILURE_COUNTERS_REDIS",
                    "subject_failures", h.subjectFailures(), "source_ip_failures", h.sourceIpFailures(),
                    "subject_medium_minimum", h.subjectMediumMinimum(), "subject_high_minimum", h.subjectHighMinimum(),
                    "source_ip_medium_minimum", h.sourceIpMediumMinimum(), "source_ip_high_minimum", h.sourceIpHighMinimum(),
                    "failure_window_seconds", h.failureWindowSeconds(),
                    "window_semantics", "COUNTER_TTL_FROM_FIRST_FAILURE", "aggregation", "MAX_ACCOUNT_AND_IP_RISK"));
        }
    }

    private static String name(Enum<?> value) { return value == null ? null : value.name(); }

    private static String safeText(String value) {
        if (value == null) return null;
        String cleaned = value.replaceAll("[\\p{Cntrl}\\u2028\\u2029]", " ");
        return cleaned.substring(0, Math.min(cleaned.length(), 120));
    }

    private static Map<String, Object> fields(Object... pairs) {
        Map<String, Object> values = new LinkedHashMap<>();
        for (int index = 0; index < pairs.length; index += 2) values.put((String) pairs[index], pairs[index + 1]);
        return values;
    }

    private Map<String, Object> feature(RiskFeatureEvidence.Status status, BigDecimal score,
                                         BigDecimal weight, Enum<?> source) {
        Map<String, Object> result = new LinkedHashMap<>();
        boolean known = status == RiskFeatureEvidence.Status.AVAILABLE;
        result.put("status", status.name());
        result.put("source", source == null ? null : source.name());
        result.put("score", known ? score : null);
        result.put("weight", weight);
        result.put("contribution", known ? weight.multiply(score) : null);
        return result;
    }

    private RiskLevel calculatedLevel(BigDecimal score) {
        if (score == null) return null;
        if (score.compareTo(policy.getThresholds().getHighMinimum()) >= 0) return RiskLevel.HIGH;
        return score.compareTo(policy.getThresholds().getMediumMinimum()) >= 0 ? RiskLevel.MEDIUM : RiskLevel.LOW;
    }

    private String numericConfigDigest() throws Exception {
        // A numeric-model fingerprint, NOT a digest of full policy/realm/network lists.
        // Explicit allowlist avoids serializing peppers, IP/CIDR lists or filesystem paths.
        var w = policy.getWeights();
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("model", policy.getModel().name() + ":1");
        config.put("weights", List.of(w.getDevice(), w.getNetwork(), w.getTemporal(), w.getAuthenticationHistory()));
        config.put("thresholds", List.of(policy.getThresholds().getMediumMinimum(), policy.getThresholds().getHighMinimum()));
        config.put("device", List.of(device.getMissing(), device.getNewDevice(), device.getPending(), device.getTrusted(), device.getRevoked()));
        config.put("network", List.of(network.isEnabled(), network.getDefaultScore(), network.getElevatedScore(), network.getHighScore()));
        config.put("temporal", List.of(temporal.getHistoryWindow().toString(), temporal.getMinimumEvents(),
                temporal.getMaximumEvents(), temporal.getZoneId().getId(), temporal.getHourTolerance(),
                temporal.getMinimumDayFrequency(), temporal.getMinimumHourFrequency(), temporal.getMediumScore(), temporal.getHighScore()));
        config.put("history", List.of(history.getSubjectMediumMinimum(), history.getSubjectHighMinimum(),
                history.getSourceIpMediumMinimum(), history.getSourceIpHighMinimum(), history.getMediumScore(), history.getHighScore()));
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(
                JSON.writeValueAsString(config).getBytes(StandardCharsets.UTF_8)));
    }
}
