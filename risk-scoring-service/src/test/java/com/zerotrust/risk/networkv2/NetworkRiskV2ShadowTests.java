package com.zerotrust.risk.networkv2;

import com.zerotrust.risk.config.NetworkRiskV2Properties;
import com.zerotrust.risk.domain.*;
import com.zerotrust.risk.dto.request.AuthenticationSuccessRequest;
import com.zerotrust.risk.service.AuthenticationHistoryKeyHasher;
import com.zerotrust.risk.service.GeoIpProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import java.math.BigDecimal;
import java.time.*;
import java.util.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class NetworkRiskV2ShadowTests {
    private final Instant now = Instant.parse("2026-11-12T12:00:00Z");
    private final NetworkRiskV2Properties properties = new NetworkRiskV2Properties();
    private final GeoIpProvider geo = mock(GeoIpProvider.class);
    private final AuthenticationHistoryKeyHasher hasher = mock(AuthenticationHistoryKeyHasher.class);
    private final NetworkContextRepository repository = mock(NetworkContextRepository.class);
    private final NetworkContextWriter writer = mock(NetworkContextWriter.class);
    private final NetworkRiskV2Trace trace = mock(NetworkRiskV2Trace.class);
    private final NetworkRiskV2WorkQueue workQueue = mock(NetworkRiskV2WorkQueue.class);
    private NetworkRiskV2Shadow shadow;
    private LoginContext context(String subject, String ip) {
        return new LoginContext(subject, "auth-session", "zerotrust-spa", ip, "synthetic-agent", "device", now);
    }
    private RiskEvaluation baseline(RiskDecision decision) {
        return new RiskEvaluation(UUID.randomUUID(), BigDecimal.valueOf(50), RiskLevel.MEDIUM,
                decision, RiskDataStatus.COMPLETE, List.of(), now);
    }
    @BeforeEach void setUp() {
        when(hasher.hash(anyString(), anyString())).thenAnswer(i -> i.getArgument(0) + ":" + i.getArgument(1));
        var clock = Clock.fixed(now, ZoneOffset.UTC);
        when(workQueue.offer(any())).thenAnswer(invocation -> { ((Runnable) invocation.getArgument(0)).run(); return true; });
        shadow = new NetworkRiskV2Shadow(properties, geo, hasher, repository,
                new NetworkRiskV2Calculator(properties), new PendingNetworkObservations(properties, clock), writer, trace, clock, workQueue);
    }
    @Test void defaultDisabledDoesNoDatabaseGeoIpHashingLearningOrTelemetry() {
        var baseline = baseline(RiskDecision.STEP_UP_MFA);
        shadow.observe(context("subject", "8.8.8.8"), baseline, 0);
        shadow.verifiedSuccess(new AuthenticationSuccessRequest("event", "subject", "zerotrust-spa", now, baseline.evaluationId()));
        verifyNoInteractions(geo, hasher, repository, writer, trace, workQueue);
        assertThat(properties.getMode()).isEqualTo(NetworkRiskV2Properties.Mode.DISABLED);
        assertThat(NetworkRiskV2Properties.Mode.values()).containsExactly(NetworkRiskV2Properties.Mode.DISABLED, NetworkRiskV2Properties.Mode.SHADOW);
    }
    @Test void deniedEvaluationNeverBecomesVerifiedHistoryEvenWithSuccessCallback() {
        properties.setMode(NetworkRiskV2Properties.Mode.SHADOW);
        var baseline = baseline(RiskDecision.DENY);
        shadow.observe(context("subject", "8.8.8.8"), baseline, 0);
        shadow.verifiedSuccess(new AuthenticationSuccessRequest("event", "subject", "zerotrust-spa", now, baseline.evaluationId()));
        verifyNoInteractions(geo, repository, writer);
    }
    @Test void onlyMatchingNativeSuccessCanLearnCapturedServerSideContextExactlyOnce() {
        properties.setMode(NetworkRiskV2Properties.Mode.SHADOW);
        when(geo.isEnabled()).thenReturn(true); when(geo.isReady()).thenReturn(true);
        when(geo.lookup("8.8.8.8")).thenReturn(GeoIpLookupResult.available(new GeoIpLocation("US", null, null, 20, 15169L, null)));
        var baseline = baseline(RiskDecision.STEP_UP_MFA);
        shadow.observe(context("subject", "8.8.8.8"), baseline, 7);
        verifyNoInteractions(writer);
        shadow.verifiedSuccess(new AuthenticationSuccessRequest("event", "other", "zerotrust-spa", now, baseline.evaluationId()));
        verifyNoInteractions(writer);
        when(writer.learn(anyString(), anyString(), anyString(), any(), any())).thenReturn(NetworkContextWriter.Outcome.RECORDED);
        var success = new AuthenticationSuccessRequest("event", "subject", "zerotrust-spa", now, baseline.evaluationId());
        shadow.verifiedSuccess(success); shadow.verifiedSuccess(success);
        var captured = ArgumentCaptor.forClass(PendingNetworkObservations.Pending.class);
        verify(writer).learn(eq("event"), eq("subject"), eq("zerotrust-spa"), eq(now), captured.capture());
        assertThat(captured.getValue().generation()).isEqualTo(7);
        assertThat(captured.getValue().observation().asn()).isEqualTo(15169);
        assertThat(captured.getValue().observation().country()).isEqualTo("US");
        assertThat(baseline.decision()).isEqualTo(RiskDecision.STEP_UP_MFA);
    }
    @Test void privateNatAddressesAreUnknownAndCannotPretendToBePublicBrowserGeoIp() {
        properties.setMode(NetworkRiskV2Properties.Mode.SHADOW);
        shadow.observe(context("subject", "172.18.0.2"), baseline(RiskDecision.ALLOW), 0);
        var assessment = ArgumentCaptor.forClass(NetworkRiskV2Assessment.class);
        verify(trace).assessment(any(), assessment.capture());
        assertThat(assessment.getValue().status()).isEqualTo(NetworkRiskV2Assessment.Status.UNAVAILABLE);
        assertThat(assessment.getValue().candidateScore()).isNull();
        verifyNoInteractions(geo);
    }
    @Test void uncorrelatedSsoAndOtherClientsDoNotLearn() {
        properties.setMode(NetworkRiskV2Properties.Mode.SHADOW);
        shadow.verifiedSuccess(new AuthenticationSuccessRequest("event", "subject", "zerotrust-spa", now));
        shadow.verifiedSuccess(new AuthenticationSuccessRequest("event", "subject", "other-client", now, UUID.randomUUID()));
        verifyNoInteractions(writer, repository, geo, hasher);
    }
    @Test void geoIpAndPersistenceFailuresDoNotChangeLiveDecision() {
        properties.setMode(NetworkRiskV2Properties.Mode.SHADOW);
        when(geo.isEnabled()).thenThrow(new IllegalStateException("synthetic-unavailable"));
        var baseline = baseline(RiskDecision.STEP_UP_MFA);
        assertThatCode(() -> shadow.observe(context("subject", "8.8.8.8"), baseline, 0)).doesNotThrowAnyException();
        assertThat(baseline.decision()).isEqualTo(RiskDecision.STEP_UP_MFA);
        verify(trace).assessment(eq(baseline), argThat(result -> result.status() == NetworkRiskV2Assessment.Status.ERROR));
    }
    @Test void structuredEvidenceOmitsIdentityIpSecretsAndCannotBreakAuthentication() {
        var lines = new ArrayList<String>();
        var trace = new NetworkRiskV2Trace(lines::add);
        trace.assessment(baseline(RiskDecision.ALLOW), NetworkRiskV2Assessment.unavailable(
                NetworkRiskV2Assessment.Status.COLD_START, "INSUFFICIENT_VERIFIED_NETWORK_HISTORY", NetworkObservation.Quality.COUNTRY_ASN));
        assertThat(lines).hasSize(1);
        assertThat(lines.get(0)).contains("\"mode\":\"SHADOW\"", "\"enforcement\":false", "evaluation_id", "network_v2")
                .doesNotContain("subject", "8.8.8.8", "password", "token", "network_hash");
        assertThatCode(() -> new NetworkRiskV2Trace(line -> { throw new IllegalStateException(); })
                .assessment(baseline(RiskDecision.ALLOW), null)).doesNotThrowAnyException();
    }
}
