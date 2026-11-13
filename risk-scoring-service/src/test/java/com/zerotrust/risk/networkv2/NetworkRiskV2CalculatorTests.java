package com.zerotrust.risk.networkv2;

import com.zerotrust.risk.config.NetworkRiskV2Properties;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;
import static org.assertj.core.api.Assertions.assertThat;

class NetworkRiskV2CalculatorTests {
    private final Instant now = Instant.parse("2026-11-12T12:00:00Z");
    private final NetworkRiskV2Calculator calculator = new NetworkRiskV2Calculator(new NetworkRiskV2Properties());
    private NetworkObservation observation(String country, Long asn, String network) {
        return new NetworkObservation(country, asn, network, 20, NetworkObservation.Quality.COUNTRY_ASN);
    }
    private NetworkHistorySample sample(String owner, String client, NetworkObservation observation, long seconds) {
        return new NetworkHistorySample(owner, client, observation, now.minusSeconds(seconds), now.minusSeconds(seconds));
    }
    private List<NetworkHistorySample> history() {
        return List.of(sample("subject", "client", observation("VN", 100L, "A"), 3600),
                sample("subject", "client", observation("VN", 100L, "A"), 86400),
                sample("subject", "client", observation("VN", 100L, "A"), 172800));
    }
    private NetworkRiskV2Assessment score(NetworkObservation current, List<NetworkHistorySample> history) {
        return calculator.calculate("subject", "client", current, history, now);
    }
    @Test void stableContextHasZeroCandidatePoints() {
        var result = score(observation("VN", 100L, "A"), history());
        assertThat(result.status()).isEqualTo(NetworkRiskV2Assessment.Status.COMPLETE);
        assertThat(result.candidateScore()).isZero();
        assertThat(result.contributions()).hasSize(3);
    }
    @Test void novelContextHasExplainableMaximum50WithNoDecisionOrDenyThreshold() {
        var result = score(observation("US", 200L, "B"), history());
        assertThat(result.candidateScore()).isEqualTo(50);
        assertThat(result.contributions()).extracting(NetworkRiskV2Assessment.Contribution::points)
                .containsExactly(20, 20, 10);
        assertThat(result.reasons()).contains("CONTEXT_NOVELTY_IS_NOT_PROOF_OF_ATTACK");
    }
    @Test void asnChangeAloneIs20AndNetworkChangeAloneIs10() {
        assertThat(score(observation("VN", 200L, "A"), history()).candidateScore()).isEqualTo(20);
        assertThat(score(observation("VN", 100L, "B"), history()).candidateScore()).isEqualTo(10);
    }
    @Test void returningToKnownCountryAndNetworkIsLowerThanUnseen() {
        var familiar = sample("subject", "client", observation("US", 200L, "B"), 172800);
        var mixed = List.of(history().get(0), history().get(1), familiar);
        assertThat(score(observation("US", 200L, "B"), mixed).candidateScore()).isEqualTo(15);
    }
    @Test void olderCountryChangeHasLowerContributionWithoutInventingTravelSpeed() {
        var old = history().stream().map(s -> new NetworkHistorySample(s.subjectHash(), s.clientId(),
                s.observation(), s.authenticatedAt().minusSeconds(86400), s.recordedAt().minusSeconds(86400))).toList();
        assertThat(score(observation("US", 200L, "B"), old).candidateScore()).isEqualTo(40);
    }
    @Test void coldStartIsUnknownRatherThanLowRisk() {
        assertThat(score(observation("VN", 100L, "A"), List.of()).candidateScore()).isNull();
        var sameDay = List.of(history().get(0), history().get(0), history().get(0));
        assertThat(score(observation("VN", 100L, "A"), sameDay).status()).isEqualTo(NetworkRiskV2Assessment.Status.COLD_START);
    }
    @Test void subjectsClientsFutureAndExpiredRecordsCannotEstablishFamiliarity() {
        var invalid = List.of(sample("other", "client", observation("US", 200L, "B"), 3600),
                sample("subject", "other", observation("US", 200L, "B"), 86400),
                sample("subject", "client", observation("US", 200L, "B"), -1),
                sample("subject", "client", observation("US", 200L, "B"), 31L * 86400),
                new NetworkHistorySample("subject", "client", observation("US", 200L, "B"), now.minusSeconds(2000), now.plusSeconds(1)));
        assertThat(score(observation("US", 200L, "B"), Stream.concat(history().stream(), invalid.stream()).toList())
                .candidateScore()).isEqualTo(50);
        assertThat(score(observation("US", 200L, "B"), invalid).historySamples()).isZero();
    }
    @Test void missingAsnAndUnavailableDataNeverBecomeZeroCandidateRisk() {
        var partial = new NetworkObservation("VN", null, "A", 50, NetworkObservation.Quality.PARTIAL);
        assertThat(score(partial, history()).status()).isEqualTo(NetworkRiskV2Assessment.Status.PARTIAL);
        assertThat(score(partial, history()).candidateScore()).isNull();
        for (var quality : List.of(NetworkObservation.Quality.GEOIP_DISABLED, NetworkObservation.Quality.GEOIP_UNAVAILABLE,
                NetworkObservation.Quality.NO_RECORD, NetworkObservation.Quality.NON_PUBLIC)) {
            var result = score(new NetworkObservation(null, null, "A", null, quality), history());
            assertThat(result.status()).isEqualTo(NetworkRiskV2Assessment.Status.UNAVAILABLE);
            assertThat(result.candidateScore()).isNull();
        }
    }
    @Test void coarseCityAccuracyIsExplicitAndDoesNotInventCountryAccuracyOrCityScoring() {
        var result = score(new NetworkObservation("US", 200L, "B", 1000, NetworkObservation.Quality.COARSE_LOCATION), history());
        assertThat(result.candidateScore()).isEqualTo(50);
        assertThat(result.quality()).isEqualTo(NetworkObservation.Quality.COARSE_LOCATION);
        assertThat(result.reasons()).contains("CITY_ACCURACY_NOT_USED_FOR_COUNTRY_OR_ASN_SCORING");
    }
}
