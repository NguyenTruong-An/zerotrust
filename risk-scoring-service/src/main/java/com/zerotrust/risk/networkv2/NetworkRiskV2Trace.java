package com.zerotrust.risk.networkv2;

import com.zerotrust.risk.domain.RiskEvaluation;
import org.jboss.logging.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

@Component
public class NetworkRiskV2Trace {
    private static final Logger LOG = Logger.getLogger(NetworkRiskV2Trace.class);
    private static final ObjectMapper JSON = new ObjectMapper();
    private final Consumer<String> sink;
    @Autowired
    public NetworkRiskV2Trace() { this(line -> LOG.info("ZEROTRUST_NETWORK_V2_SHADOW " + line)); }
    public NetworkRiskV2Trace(Consumer<String> sink) { this.sink = sink; }

    public void assessment(RiskEvaluation baseline, NetworkRiskV2Assessment assessment) {
        try {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("schema_version", 1); row.put("model_version", NetworkRiskV2Calculator.VERSION);
            row.put("mode", "SHADOW"); row.put("enforcement", false);
            row.put("evaluation_id", baseline.evaluationId()); row.put("live_decision", baseline.decision());
            row.put("live_risk_score", baseline.riskScore()); row.put("live_data_status", baseline.dataStatus());
            row.put("network_v2", assessment);
            sink.accept(JSON.writeValueAsString(row));
        } catch (Exception | LinkageError ignored) { /* Telemetry cannot change authentication. */ }
    }
    public void learning(UUID evaluationId, String outcome) {
        try {
            sink.accept(JSON.writeValueAsString(Map.of("schema_version", 1, "mode", "SHADOW",
                    "stage", "VERIFIED_NETWORK_LEARNING", "evaluation_id", evaluationId.toString(), "outcome", outcome)));
        } catch (Exception | LinkageError ignored) { /* No identifiers or exception text in logs. */ }
    }
}
