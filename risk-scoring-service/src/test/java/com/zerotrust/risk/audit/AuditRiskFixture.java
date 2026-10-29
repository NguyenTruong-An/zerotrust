package com.zerotrust.risk.audit;

import com.zerotrust.risk.config.*;
import com.zerotrust.risk.domain.*;
import com.zerotrust.risk.entity.KnownDeviceEntity;
import com.zerotrust.risk.feature.DatabaseBackedRiskFeatureExtractor;
import com.zerotrust.risk.repository.*;
import com.zerotrust.risk.rule.PrioritySecurityRuleEvaluator;
import com.zerotrust.risk.service.*;
import org.springframework.dao.DataRetrievalFailureException;

import java.lang.reflect.Proxy;
import java.math.BigDecimal;
import java.time.*;
import java.util.*;
import java.util.function.Function;

/** Synthetic, read-only data sources. Scoring, extraction and all four calculators are real. */
final class AuditRiskFixture {
    static final Instant NOW = Instant.parse("2026-09-21T08:00:00Z");
    enum Device { MISSING, NEW, PENDING, TRUSTED, EXPIRED, MFA_RESET, SECURITY_REVOKED }
    Device device = Device.TRUSTED;
    long subjectFailures;
    long ipFailures;
    int failedCounter; // 1 = subject read; 2 = IP read
    boolean temporalUnavailable;
    List<Instant> history = history(6, 6);
    Instant now = NOW;
    Instant trustedAt = NOW.minus(Duration.ofDays(1));
    String ip = "10.1.2.3";
    final RiskPolicyProperties policy = policy("0.25", "0.25", "0.25", "0.25");
    final NetworkRiskProperties network = networkPolicy();
    final TemporalRiskProperties temporal = temporalPolicy();
    final AuthenticationHistoryRiskProperties authentication = authenticationPolicy();
    final DeviceRiskProperties devices = devicePolicy();
    GeoIpProvider geoIp = geoIp(false, GeoIpLookupResult.disabled());

    LoginContext context() {
        return new LoginContext("qa-subject", "qa-session", "qa-client", ip, null,
                device == Device.MISSING ? null : "qa-device", now);
    }

    DeviceRecognitionService recognition() {
        DeviceFingerprintProperties props = new DeviceFingerprintProperties();
        props.setPepper("independent-audit-synthetic-fixture-pepper");
        DeviceFingerprintHasher hasher = new DeviceFingerprintHasher(props);
        KnownDeviceRepository repository = repository(KnownDeviceRepository.class, args -> {
            if (device == Device.NEW || device == Device.MISSING) return Optional.empty();
            Instant first = trustedAt.minus(Duration.ofDays(60));
            KnownDeviceEntity entity = new KnownDeviceEntity("qa-subject", (String) args[1], first);
            switch (device) {
                case TRUSTED -> entity.trust(trustedAt);
                case EXPIRED -> entity.trust(now.minus(Duration.ofDays(30)));
                case MFA_RESET -> entity.revokeForMfaReset(now.minusSeconds(1));
                case SECURITY_REVOKED -> entity.revoke(now.minusSeconds(1));
                default -> { }
            }
            return Optional.of(entity);
        }, "findBySubjectIdAndDeviceFingerprintHash");
        return new DeviceRecognitionService(hasher, repository);
    }

    AuthenticationHistoryRiskCalculator historyCalculator() {
        AuthenticationFailureStore store = new AuthenticationFailureStore() {
            public boolean recordFailure(String event, String subject, String address) {
                throw new AssertionError("audit must not write failure events");
            }
            public long countBySubject(String subject) {
                if (failedCounter == 1) throw new DataRetrievalFailureException("synthetic subject outage");
                return subjectFailures;
            }
            public long countBySourceIp(String address) {
                if (failedCounter == 2) throw new DataRetrievalFailureException("synthetic IP outage");
                return ipFailures;
            }
        };
        return new AuthenticationHistoryRiskCalculator(store, authentication, policy);
    }

    TemporalRiskCalculator temporalCalculator() {
        AuthenticationSuccessEventRepository repository = repository(
                AuthenticationSuccessEventRepository.class, args -> {
                    if (temporalUnavailable) throw new DataRetrievalFailureException("synthetic history outage");
                    return history;
                }, "findRecentAuthenticationTimes");
        return new TemporalRiskCalculator(repository, temporal, policy);
    }

    NetworkRiskCalculator networkCalculator() { return new NetworkRiskCalculator(network, geoIp); }

    DatabaseBackedRiskFeatureExtractor extractor() {
        return new DatabaseBackedRiskFeatureExtractor(recognition(), devices, historyCalculator(),
                temporalCalculator(), networkCalculator());
    }

    RiskEvaluation evaluate() {
        return new RiskEvaluationService(new PrioritySecurityRuleEvaluator(List.of()), extractor(),
                new RiskScoringService(policy), trace(line -> { })).evaluate(context());
    }

    com.zerotrust.risk.trace.RiskScoreTrace trace(java.util.function.Consumer<String> sink) {
        return new com.zerotrust.risk.trace.RiskScoreTrace(policy, devices, network, temporal, authentication, sink);
    }

    @SuppressWarnings("unchecked")
    private static <T> T repository(Class<T> type, Function<Object[], Object> query, String name) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type},
                (proxy, method, args) -> {
                    if (method.getName().equals(name)) return query.apply(args);
                    throw new AssertionError("unexpected repository operation: " + method.getName());
                });
    }

    static RiskPolicyProperties policy(String... values) {
        RiskPolicyProperties p = new RiskPolicyProperties();
        p.getWeights().setDevice(new BigDecimal(values[0]));
        p.getWeights().setNetwork(new BigDecimal(values[1]));
        p.getWeights().setTemporal(new BigDecimal(values[2]));
        p.getWeights().setAuthenticationHistory(new BigDecimal(values[3]));
        p.getThresholds().setMediumMinimum(new BigDecimal("40"));
        p.getThresholds().setHighMinimum(new BigDecimal("75"));
        return p;
    }

    static NetworkRiskProperties networkPolicy() {
        NetworkRiskProperties p = new NetworkRiskProperties();
        p.setEnabled(true);
        p.setDefaultScore(new BigDecimal("50"));
        p.setElevatedScore(new BigDecimal("50"));
        p.setHighScore(new BigDecimal("100"));
        p.setTrustedCidrs(List.of("10.0.0.0/8"));
        p.setElevatedRiskCidrs(List.of("198.51.100.0/24"));
        p.setHighRiskCidrs(List.of("203.0.113.0/24"));
        return p;
    }

    static AuthenticationHistoryRiskProperties authenticationPolicy() {
        AuthenticationHistoryRiskProperties p = new AuthenticationHistoryRiskProperties();
        p.setSubjectMediumMinimum(3); p.setSubjectHighMinimum(5);
        p.setSourceIpMediumMinimum(10); p.setSourceIpHighMinimum(20);
        p.setMediumScore(new BigDecimal("50")); p.setHighScore(new BigDecimal("100"));
        return p;
    }

    static DeviceRiskProperties devicePolicy() {
        DeviceRiskProperties p = new DeviceRiskProperties();
        p.setMissing(new BigDecimal("80")); p.setNewDevice(new BigDecimal("60"));
        p.setPending(new BigDecimal("50")); p.setTrusted(BigDecimal.ZERO);
        p.setRevoked(new BigDecimal("100"));
        return p;
    }

    static TemporalRiskProperties temporalPolicy() {
        TemporalRiskProperties p = new TemporalRiskProperties();
        p.setHistoryWindow(Duration.ofDays(90)); p.setMinimumEvents(5); p.setMaximumEvents(200);
        p.setZoneId(ZoneOffset.UTC); p.setHourTolerance(1);
        p.setMinimumDayFrequency(new BigDecimal("0.10"));
        p.setMinimumHourFrequency(new BigDecimal("0.20"));
        p.setMediumScore(new BigDecimal("50")); p.setHighScore(new BigDecimal("100"));
        return p;
    }

    static List<Instant> history(int size, int matches) {
        List<Instant> result = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            Instant prior = NOW.minus(Duration.ofDays(7L * (i + 1)));
            result.add(i < matches ? prior : prior.plus(Duration.ofHours(30)));
        }
        return result;
    }

    static GeoIpProvider geoIp(boolean enabled, GeoIpLookupResult result) {
        return new GeoIpProvider() {
            public boolean isEnabled() { return enabled; }
            public boolean isReady() { return enabled; }
            public GeoIpLookupResult lookup(String address) {
                if (!enabled) throw new AssertionError("disabled provider must not be queried");
                return result;
            }
        };
    }
}
