package com.zerotrust.risk.networkv2;

import com.zerotrust.risk.config.NetworkRiskV2Properties;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

@Component
public class NetworkRiskV2Calculator {
    public static final String VERSION = "NETWORK_CONTEXT_V2_SHADOW:1";
    private final NetworkRiskV2Properties properties;

    public NetworkRiskV2Calculator(NetworkRiskV2Properties properties) { this.properties = properties; }

    public NetworkRiskV2Assessment calculate(String subjectHash, String clientId,
            NetworkObservation current, List<NetworkHistorySample> supplied, Instant now) {
        if (current == null || current.networkHash() == null) {
            return NetworkRiskV2Assessment.unavailable(NetworkRiskV2Assessment.Status.UNAVAILABLE,
                    "NETWORK_EVIDENCE_UNAVAILABLE", current == null ? null : current.quality());
        }
        if (!current.complete()) {
            boolean partial = current.quality() == NetworkObservation.Quality.PARTIAL;
            return NetworkRiskV2Assessment.unavailable(partial ? NetworkRiskV2Assessment.Status.PARTIAL
                            : NetworkRiskV2Assessment.Status.UNAVAILABLE,
                    partial ? "COUNTRY_OR_ASN_MISSING_NOT_ZERO_RISK" : "GEOIP_EVIDENCE_UNAVAILABLE_NOT_ZERO_RISK", current.quality());
        }
        Instant start = now.minus(Duration.ofDays(properties.getHistoryDays()));
        // Defense in depth: even a faulty repository/caller cannot mix subjects or clients.
        List<NetworkHistorySample> history = supplied.stream()
                .filter(s -> subjectHash.equals(s.subjectHash()) && clientId.equals(s.clientId()))
                .filter(s -> s.authenticatedAt() != null && s.recordedAt() != null)
                .filter(s -> !s.authenticatedAt().isBefore(start) && s.authenticatedAt().isBefore(now)
                        && !s.recordedAt().isAfter(now))
                .filter(s -> s.observation() != null && s.observation().complete())
                .sorted(Comparator.comparing(NetworkHistorySample::authenticatedAt).reversed())
                .limit(properties.getHistoryLimit()).toList();
        int days = (int) history.stream().map(s -> s.authenticatedAt().atZone(ZoneOffset.UTC).toLocalDate())
                .distinct().count();
        if (history.size() < properties.getMinimumSamples() || days < properties.getMinimumDistinctDays()) {
            return new NetworkRiskV2Assessment(NetworkRiskV2Assessment.Status.COLD_START, null,
                    List.of(), List.of("INSUFFICIENT_VERIFIED_NETWORK_HISTORY"), history.size(), days, current.quality(), current.accuracyRadiusKm());
        }
        NetworkHistorySample latest = history.get(0);
        boolean familiarAsn = history.stream().anyMatch(s -> Objects.equals(s.observation().asn(), current.asn()));
        boolean familiarCountry = history.stream().anyMatch(s -> current.country().equals(s.observation().country()));
        boolean countryChanged = !current.country().equals(latest.observation().country());
        boolean recent = Duration.between(latest.authenticatedAt(), now).compareTo(Duration.ofHours(6)) <= 0;
        int asnPoints = familiarAsn ? 0 : 20;
        int countryPoints = !countryChanged ? 0 : recent ? (familiarCountry ? 10 : 20) : (familiarCountry ? 5 : 10);
        boolean sameNetwork = current.networkHash().equals(latest.observation().networkHash());
        boolean familiarNetwork = history.stream().anyMatch(s -> current.networkHash().equals(s.observation().networkHash()));
        int networkPoints = sameNetwork ? 0 : familiarNetwork ? 5 : 10;
        List<String> reasons = new ArrayList<>();
        if (!familiarAsn) reasons.add("ASN_NOT_SEEN_FOR_THIS_SUBJECT");
        if (countryChanged) reasons.add(recent ? "RECENT_COUNTRY_CHANGE" : "COUNTRY_CHANGE");
        if (!sameNetwork) reasons.add("OBSERVED_NETWORK_CONTEXT_CHANGED");
        if (current.quality() != NetworkObservation.Quality.COUNTRY_ASN) reasons.add("CITY_ACCURACY_NOT_USED_FOR_COUNTRY_OR_ASN_SCORING");
        reasons.add("CONTEXT_NOVELTY_IS_NOT_PROOF_OF_ATTACK");
        return new NetworkRiskV2Assessment(NetworkRiskV2Assessment.Status.COMPLETE,
                asnPoints + countryPoints + networkPoints,
                List.of(new NetworkRiskV2Assessment.Contribution("ASN_FAMILIARITY", asnPoints, familiarAsn ? "SEEN" : "NEW"),
                        new NetworkRiskV2Assessment.Contribution("COUNTRY_CHANGE", countryPoints,
                                !countryChanged ? "UNCHANGED" : familiarCountry ? "KNOWN_COUNTRY_RETURN" : "NEW_COUNTRY"),
                        new NetworkRiskV2Assessment.Contribution("NETWORK_CHANGE", networkPoints,
                                sameNetwork ? "UNCHANGED" : familiarNetwork ? "KNOWN_CONTEXT_RETURN" : "NEW_CONTEXT")),
                List.copyOf(reasons), history.size(), days, current.quality(), current.accuracyRadiusKm());
    }
}
