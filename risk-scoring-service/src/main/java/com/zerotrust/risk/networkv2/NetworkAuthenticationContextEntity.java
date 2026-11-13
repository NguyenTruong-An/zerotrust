package com.zerotrust.risk.networkv2;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "network_authentication_contexts")
public class NetworkAuthenticationContextEntity {
    @Id @Column(name = "event_id", length = 255) private String eventId;
    @Column(name = "subject_hash", nullable = false, length = 64) private String subjectHash;
    @Column(name = "client_id", nullable = false, length = 255) private String clientId;
    @Column(name = "country_code", length = 2) private String country;
    @Column(name = "asn_number") private Long asn;
    @Column(name = "network_hash", nullable = false, length = 64) private String networkHash;
    @Column(name = "accuracy_radius_km") private Integer accuracyRadiusKm;
    @Enumerated(EnumType.STRING) @Column(name = "evidence_quality", nullable = false, length = 32)
    private NetworkObservation.Quality quality;
    @Column(name = "authenticated_at", nullable = false, columnDefinition = "TIMESTAMP(6)") private Instant authenticatedAt;
    @Column(name = "recorded_at", nullable = false, columnDefinition = "TIMESTAMP(6)") private Instant recordedAt;

    public NetworkAuthenticationContextEntity(String eventId, String subjectHash, String clientId,
            NetworkObservation observation, Instant authenticatedAt, Instant recordedAt) {
        this.eventId = eventId; this.subjectHash = subjectHash; this.clientId = clientId;
        this.country = observation.country(); this.asn = observation.asn();
        this.networkHash = observation.networkHash(); this.accuracyRadiusKm = observation.accuracyRadiusKm();
        this.quality = observation.quality(); this.authenticatedAt = authenticatedAt; this.recordedAt = recordedAt;
    }
    public NetworkHistorySample sample() {
        return new NetworkHistorySample(subjectHash, clientId,
                new NetworkObservation(country, asn, networkHash, accuracyRadiusKm, quality), authenticatedAt, recordedAt);
    }
}
