package com.zerotrust.risk.audit;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.zerotrust.risk.config.AuthenticationHistoryProperties;
import com.zerotrust.risk.domain.*;
import com.zerotrust.risk.repository.AuthenticationFailureStore;
import com.zerotrust.risk.rule.PrioritySecurityRuleEvaluator;
import com.zerotrust.risk.service.*;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class RiskObservationTests {
    private final ObjectMapper json = new ObjectMapper();

    @Test
    void oneEvaluationExplainsActualInputsContributionsAndMandatoryMfaWithoutRawContext() throws Exception {
        AuditRiskFixture f = new AuditRiskFixture();
        f.device = AuditRiskFixture.Device.NEW;
        f.ip = "8.8.8.8";
        f.geoIp = AuditRiskFixture.geoIp(true, GeoIpLookupResult.available(
                new GeoIpLocation("VN", "Lab\nCity", "Asia/Ho_Chi_Minh", 20, 64512L, "Lab Network")));
        List<String> lines = new ArrayList<>();
        RiskEvaluation result = new RiskEvaluationService(new PrioritySecurityRuleEvaluator(List.of()), f.extractor(),
                new RiskScoringService(f.policy), f.trace(lines::add)).evaluate(f.context());
        JsonNode trace = json.readTree(lines.get(0));
        assertThat(result.riskScore()).isEqualByComparingTo("27.50");
        assertThat(result.decision()).isEqualTo(RiskDecision.STEP_UP_MFA);
        assertThat(trace.path("evaluation_id").asText()).isEqualTo(result.evaluationId().toString());
        assertThat(trace.path("calculated_level").asText()).isEqualTo("LOW");
        assertThat(trace.path("effective_level").asText()).isEqualTo("MEDIUM");
        assertThat(trace.path("decision_source").asText()).isEqualTo("MANDATORY_STEP_UP");
        assertThat(trace.path("mandatory_step_up_reason").asText()).isEqualTo("NEW_DEVICE");
        assertThat(trace.at("/features/device/inputs/recognition_reason").asText()).isEqualTo("NOT_REGISTERED");
        assertThat(trace.at("/features/network/inputs/geoip_status").asText()).isEqualTo("AVAILABLE");
        assertThat(trace.at("/features/network/inputs/ip_source").asText()).isEqualTo("RISK_REQUEST_IP_ADDRESS");
        assertThat(trace.at("/features/network/inputs/country_code").asText()).isEqualTo("VN");
        assertThat(trace.at("/features/network/inputs/city_name").asText()).isEqualTo("Lab City");
        assertThat(trace.at("/features/network/inputs/asn").asLong()).isEqualTo(64512);
        assertThat(trace.at("/features/network/contribution").decimalValue()).isEqualByComparingTo("12.5");
        assertThat(trace.at("/features/temporal/inputs/sample_size").asInt()).isEqualTo(6);
        assertThat(trace.at("/features/temporal/inputs/matching_hours").asInt()).isEqualTo(6);
        assertThat(trace.at("/features/authentication_history/inputs/subject_failures").asInt()).isZero();
        assertThat(lines.get(0)).doesNotContain("8.8.8.8", "qa-subject", "qa-session", "qa-device", "qa-client",
                "synthetic-fixture-pepper", "10.0.0.0/8");
    }

    @Test
    void snapshotDoesNotReReadMutableStoresWhenExplanationIsWritten() throws Exception {
        AuditRiskFixture f = new AuditRiskFixture();
        f.subjectFailures = 3;
        RiskFeatureExtraction extraction = f.extractor().extract(f.context());
        f.subjectFailures = 999;
        f.ipFailures = 999;
        f.history = List.of();
        List<String> lines = new ArrayList<>();
        f.trace(lines::add).record(new RiskScoringService(f.policy).evaluate(extraction.factors()), extraction, 0);
        JsonNode trace = json.readTree(lines.get(0));
        assertThat(trace.at("/features/authentication_history/inputs/subject_failures").asInt()).isEqualTo(3);
        assertThat(trace.at("/features/temporal/inputs/sample_size").asInt()).isEqualTo(6);
    }

    @Test
    void cidrPrecedenceDoesNotPerformAnExtraGeoIpLookupForTheViewer() throws Exception {
        AuditRiskFixture f = new AuditRiskFixture();
        GeoIpProvider provider = mock(GeoIpProvider.class);
        f.geoIp = provider;
        RiskFeatureExtraction extraction = f.extractor().extract(f.context());
        assertThat(extraction.evidence().signals().network().observation().geoIpUse())
                .isEqualTo(NetworkRiskAssessment.GeoIpUse.SKIPPED_CIDR_MATCH);
        verifyNoInteractions(provider);
        assertThat(extraction.factors().networkRisk()).isEqualByComparingTo(BigDecimal.ZERO);
    }

    @Test
    void unavailableGeoIpAndColdStartRemainUnknownRatherThanSafeZeroScores() throws Exception {
        AuditRiskFixture f = new AuditRiskFixture();
        f.ip = "8.8.8.8";
        f.history = List.of();
        f.geoIp = AuditRiskFixture.geoIp(true, GeoIpLookupResult.notFound());
        List<String> lines = new ArrayList<>();
        RiskEvaluation result = new RiskEvaluationService(new PrioritySecurityRuleEvaluator(List.of()), f.extractor(),
                new RiskScoringService(f.policy), f.trace(lines::add)).evaluate(f.context());
        JsonNode trace = json.readTree(lines.get(0));
        assertThat(result.riskScore()).isNull();
        assertThat(result.dataStatus()).isEqualTo(RiskDataStatus.INCOMPLETE);
        assertThat(trace.at("/features/network/score").isNull()).isTrue();
        assertThat(trace.at("/features/network/inputs/geoip_status").asText()).isEqualTo("NOT_FOUND");
        assertThat(trace.at("/features/temporal/status").asText()).isEqualTo("COLD_START");
        assertThat(trace.at("/features/temporal/inputs/sample_size").asInt()).isZero();
        assertThat(trace.at("/features/temporal/inputs/matching_days").isNull()).isTrue();
    }

    @Test
    void priorityExitDoesNotInventAWeightedScoreOrComponents() throws Exception {
        AuditRiskFixture f = new AuditRiskFixture();
        f.device = AuditRiskFixture.Device.SECURITY_REVOKED;
        List<String> lines = new ArrayList<>();
        RiskEvaluation result = new RiskEvaluationService(new PrioritySecurityRuleEvaluator(List.of()), f.extractor(),
                new RiskScoringService(f.policy), f.trace(lines::add)).evaluate(f.context());
        JsonNode trace = json.readTree(lines.get(0));
        assertThat(result.decision()).isEqualTo(RiskDecision.DENY);
        assertThat(trace.path("risk_score").isNull()).isTrue();
        assertThat(trace.path("features").isNull()).isTrue();
        assertThat(trace.path("decision_source").asText()).isEqualTo("PRIORITY_RULE");
    }

    @Test
    void deviceExplanationDistinguishesExpiryAndMfaReset() {
        AuditRiskFixture f = new AuditRiskFixture();
        f.device = AuditRiskFixture.Device.EXPIRED;
        assertThat(f.recognition().recognize(f.context()).reason()).isEqualTo(DeviceRecognition.Reason.TRUST_EXPIRED);
        f.device = AuditRiskFixture.Device.MFA_RESET;
        assertThat(f.recognition().recognize(f.context()).reason()).isEqualTo(DeviceRecognition.Reason.MFA_RESET);
    }

    @Test
    void historyEvidenceUsesTheSameTwoReadsAndConfiguredCounterTtl() {
        AuditRiskFixture f = new AuditRiskFixture();
        AuthenticationFailureStore store = mock(AuthenticationFailureStore.class);
        when(store.countBySubject("qa-subject")).thenReturn(3L);
        when(store.countBySourceIp(f.ip)).thenReturn(20L);
        AuthenticationHistoryProperties storage = new AuthenticationHistoryProperties();
        storage.setFailureWindow(Duration.ofMinutes(15));
        var assessment = new AuthenticationHistoryRiskCalculator(store, f.authentication, f.policy, storage)
                .calculate(f.context()).orElseThrow();
        assertThat(assessment.riskScore()).isEqualByComparingTo("100");
        assertThat(assessment.evidence().subjectFailures()).isEqualTo(3);
        assertThat(assessment.evidence().sourceIpFailures()).isEqualTo(20);
        assertThat(assessment.evidence().failureWindowSeconds()).isEqualTo(900);
        verify(store).countBySubject("qa-subject");
        verify(store).countBySourceIp(f.ip);
        verifyNoMoreInteractions(store);
    }

    @Test
    void brokenTraceCannotChangeBaselineDecision() {
        AuditRiskFixture f = new AuditRiskFixture();
        f.device = AuditRiskFixture.Device.NEW;
        RiskEvaluation result = new RiskEvaluationService(new PrioritySecurityRuleEvaluator(List.of()), f.extractor(),
                new RiskScoringService(f.policy), f.trace(line -> { throw new IllegalStateException("sink failure"); }))
                .evaluate(f.context());
        assertThat(result.riskScore()).isEqualByComparingTo("15");
        assertThat(result.decision()).isEqualTo(RiskDecision.STEP_UP_MFA);
    }
}
