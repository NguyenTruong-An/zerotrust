package com.zerotrust.risk.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.persistence.Version;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Objects;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(
        name = "known_devices",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_known_devices_subject_fingerprint",
                columnNames = {"subject_id", "device_fingerprint_hash"}
        )
)
public class KnownDeviceEntity {

    private static final int SHA_256_HEX_LENGTH = 64;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "subject_id", nullable = false, length = 255)
    private String subjectId;

    @Column(
            name = "device_fingerprint_hash",
            nullable = false,
            length = SHA_256_HEX_LENGTH,
            columnDefinition = "CHAR(64)"
    )
    private String deviceFingerprintHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private DeviceStatus status;

    @Column(name = "first_seen_at", nullable = false, columnDefinition = "TIMESTAMP(6)")
    private Instant firstSeenAt;

    @Column(name = "last_seen_at", nullable = false, columnDefinition = "TIMESTAMP(6)")
    private Instant lastSeenAt;

    @Column(name = "trusted_at", columnDefinition = "TIMESTAMP(6)")
    private Instant trustedAt;

    @Column(name = "revoked_at", columnDefinition = "TIMESTAMP(6)")
    private Instant revokedAt;

    @Version
    @Column(name = "version", nullable = false)
    private long version;

    public KnownDeviceEntity(String subjectId, String deviceFingerprintHash, Instant firstSeenAt) {
        this.subjectId = requireText(subjectId, "subjectId");
        this.deviceFingerprintHash = requireSha256Hex(deviceFingerprintHash);
        this.firstSeenAt = Objects.requireNonNull(firstSeenAt, "firstSeenAt must not be null");
        this.lastSeenAt = firstSeenAt;
        this.status = DeviceStatus.PENDING;
    }

    public void markSeen(Instant seenAt) {
        Objects.requireNonNull(seenAt, "seenAt must not be null");
        if (seenAt.isAfter(lastSeenAt)) {
            lastSeenAt = seenAt;
        }
    }

    public void trust(Instant trustedAt) {
        Objects.requireNonNull(trustedAt, "trustedAt must not be null");
        status = DeviceStatus.TRUSTED;
        this.trustedAt = trustedAt;
        revokedAt = null;
        markSeen(trustedAt);
    }

    public void revoke(Instant revokedAt) {
        this.revokedAt = Objects.requireNonNull(revokedAt, "revokedAt must not be null");
        status = DeviceStatus.REVOKED;
        markSeen(revokedAt);
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }

    private static String requireSha256Hex(String value) {
        if (value == null
                || value.length() != SHA_256_HEX_LENGTH
                || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(
                    "deviceFingerprintHash must be a lowercase SHA-256 hex value"
            );
        }
        return value;
    }
}
