package com.zerotrust.risk.networkv2;

import com.zerotrust.risk.config.NetworkRiskV2Properties;
import com.zerotrust.risk.domain.*;
import com.zerotrust.risk.dto.request.AuthenticationSuccessRequest;
import com.zerotrust.risk.service.AuthenticationHistoryKeyHasher;
import com.zerotrust.risk.service.GeoIpProvider;
import com.zerotrust.risk.validation.IpAddressNormalizer;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
public class NetworkRiskV2Shadow {
    private final NetworkRiskV2Properties properties;
    private final GeoIpProvider geoIp;
    private final AuthenticationHistoryKeyHasher hasher;
    private final NetworkContextRepository repository;
    private final NetworkRiskV2Calculator calculator;
    private final PendingNetworkObservations pending;
    private final NetworkContextWriter writer;
    private final NetworkRiskV2Trace trace;
    private final Clock clock;
    private final NetworkRiskV2WorkQueue workQueue;

    public void observe(LoginContext context, RiskEvaluation baseline, long generation) {
        if (!properties.isShadow() || !properties.getMonitoredClientId().equals(context.clientId().trim())) return;
        workQueue.offer(() -> observeNow(context, baseline, generation));
    }

    private void observeNow(LoginContext context, RiskEvaluation baseline, long generation) {
        try {
            if (!context.receivedAt().plus(properties.getPendingTtl()).isAfter(clock.instant())) {
                trace.assessment(baseline, NetworkRiskV2Assessment.unavailable(NetworkRiskV2Assessment.Status.SKIPPED,
                        "OBSERVATION_EXPIRED_QUEUE_DELAY", null));
                return;
            }
            if (baseline.decision() == RiskDecision.DENY) {
                trace.assessment(baseline, NetworkRiskV2Assessment.unavailable(NetworkRiskV2Assessment.Status.SKIPPED,
                        "BASELINE_DENIED_NOT_LEARNING", null));
                return;
            }
            Instant now = context.receivedAt();
            String owner = subjectHash(context.subjectId());
            NetworkObservation observation = observation(context.ipAddress());
            List<NetworkHistorySample> history = repository.recent(owner, context.clientId().trim(),
                    now.minus(Duration.ofDays(properties.getHistoryDays())), now,
                    PageRequest.of(0, properties.getHistoryLimit())).stream().map(NetworkAuthenticationContextEntity::sample).toList();
            NetworkRiskV2Assessment result = calculator.calculate(owner, context.clientId().trim(), observation, history, now);
            pending.remember(baseline.evaluationId(), new PendingNetworkObservations.Pending(owner,
                    context.clientId().trim(), observation, now, generation));
            trace.assessment(baseline, result);
        } catch (RuntimeException | LinkageError ignored) {
            trace.assessment(baseline, NetworkRiskV2Assessment.unavailable(NetworkRiskV2Assessment.Status.ERROR,
                    "SHADOW_UNAVAILABLE_LIVE_DECISION_UNCHANGED", null));
        }
    }

    /** Called only after a newly inserted, authorized native Keycloak LOGIN event. */
    public void verifiedSuccess(AuthenticationSuccessRequest request) {
        if (!properties.isShadow() || request.riskEvaluationId() == null
                || !properties.getMonitoredClientId().equals(request.clientId().trim())) return;
        workQueue.offer(() -> verifiedSuccessNow(request));
    }

    private void verifiedSuccessNow(AuthenticationSuccessRequest request) {
        try {
            var observation = pending.consume(request.riskEvaluationId(), subjectHash(request.subjectId()), request.clientId().trim());
            if (observation == null) {
                trace.learning(request.riskEvaluationId(), "NO_MATCHING_EVALUATION_NOT_LEARNING");
                return;
            }
            NetworkContextWriter.Outcome outcome = writer.learn(request.eventId().trim(),
                    SubjectIdentifierNormalizer.normalize(request.subjectId()), request.clientId().trim(),
                    request.authenticatedAt(), observation);
            trace.learning(request.riskEvaluationId(), outcome.name());
        } catch (RuntimeException | LinkageError ignored) {
            trace.learning(request.riskEvaluationId(), "SHADOW_WRITE_FAILED_AUTHENTICATION_UNCHANGED");
        }
    }

    private String subjectHash(String subject) {
        return hasher.hash("network-v2-subject", SubjectIdentifierNormalizer.normalize(subject));
    }

    private NetworkObservation observation(String ip) {
        String address = IpAddressNormalizer.normalize(ip);
        if (!NetworkAddressScope.isPublic(address))
            return new NetworkObservation(null, null, null, null, NetworkObservation.Quality.NON_PUBLIC);
        String networkHash = hasher.hash("network-v2-address", address);
        if (!geoIp.isEnabled()) return new NetworkObservation(null, null, networkHash, null, NetworkObservation.Quality.GEOIP_DISABLED);
        if (!geoIp.isReady()) return new NetworkObservation(null, null, networkHash, null, NetworkObservation.Quality.GEOIP_UNAVAILABLE);
        GeoIpLookupResult result = geoIp.lookup(address);
        if (result == null || result.status() != GeoIpLookupStatus.AVAILABLE)
            return new NetworkObservation(null, null, networkHash, null,
                    result != null && result.status() == GeoIpLookupStatus.NOT_FOUND
                            ? NetworkObservation.Quality.NO_RECORD : NetworkObservation.Quality.GEOIP_UNAVAILABLE);
        GeoIpLocation location = result.location();
        NetworkObservation.Quality quality = location.countryCode() == null || location.autonomousSystemNumber() == null
                || location.autonomousSystemNumber() <= 0 ? NetworkObservation.Quality.PARTIAL
                : location.accuracyRadiusKm() == null ? NetworkObservation.Quality.UNKNOWN_ACCURACY
                : location.accuracyRadiusKm() > 500 ? NetworkObservation.Quality.COARSE_LOCATION : NetworkObservation.Quality.COUNTRY_ASN;
        return new NetworkObservation(location.countryCode(), location.autonomousSystemNumber(), networkHash,
                location.accuracyRadiusKm(), quality);
    }
}
