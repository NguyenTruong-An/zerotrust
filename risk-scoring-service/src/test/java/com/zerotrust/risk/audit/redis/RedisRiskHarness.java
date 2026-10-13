package com.zerotrust.risk.audit.redis;

import com.zerotrust.risk.config.*;
import com.zerotrust.risk.domain.*;
import com.zerotrust.risk.feature.DatabaseBackedRiskFeatureExtractor;
import com.zerotrust.risk.repository.AuthenticationFailureStore;
import com.zerotrust.risk.rule.PrioritySecurityRuleEvaluator;
import com.zerotrust.risk.service.*;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/** History store/calculator, extractor, evaluator and scoring are real. Other feature sources are controlled. */
final class RedisRiskHarness {
    static final String SUBJECT = "subject1", IP = "203.0.113.10";
    static LoginContext context() {
        return new LoginContext(SUBJECT, "qa-session", "qa-client", IP, "qa-agent", "qa-device", Instant.now());
    }
    static RiskEvaluation evaluate(AuthenticationFailureStore store) { return evaluate(store, false); }
    static RiskEvaluation evaluate(AuthenticationFailureStore store, boolean revoked) {
        DeviceRecognitionService device = mock(DeviceRecognitionService.class);
        when(device.recognize(any())).thenReturn(new DeviceRecognition(
                revoked ? DeviceRecognitionStatus.REVOKED : DeviceRecognitionStatus.TRUSTED, "qa-controlled-fingerprint"));
        TemporalRiskCalculator temporal = mock(TemporalRiskCalculator.class);
        when(temporal.calculate(any())).thenReturn(TemporalRiskAssessment.available(BigDecimal.ZERO));
        NetworkRiskCalculator network = mock(NetworkRiskCalculator.class);
        when(network.calculate(any())).thenReturn(NetworkRiskAssessment.available(BigDecimal.ZERO));
        DeviceRiskProperties devicePolicy = new DeviceRiskProperties();
        devicePolicy.setTrusted(BigDecimal.ZERO); devicePolicy.setRevoked(new BigDecimal("100"));
        devicePolicy.setMissing(new BigDecimal("80")); devicePolicy.setNewDevice(new BigDecimal("60")); devicePolicy.setPending(new BigDecimal("50"));
        RiskPolicyProperties policy = new RiskPolicyProperties();
        policy.getWeights().setDevice(new BigDecimal("0.25")); policy.getWeights().setNetwork(new BigDecimal("0.25"));
        policy.getWeights().setTemporal(new BigDecimal("0.25")); policy.getWeights().setAuthenticationHistory(new BigDecimal("0.25"));
        policy.getThresholds().setMediumMinimum(new BigDecimal("40")); policy.getThresholds().setHighMinimum(new BigDecimal("75"));
        var extractor = new DatabaseBackedRiskFeatureExtractor(device, devicePolicy,
                new AuthenticationHistoryRiskCalculator(store, RedisAuditSupport.thresholds()), temporal, network);
        return new RiskEvaluationService(new PrioritySecurityRuleEvaluator(List.of()), extractor, new RiskScoringService(policy)).evaluate(context());
    }
}
