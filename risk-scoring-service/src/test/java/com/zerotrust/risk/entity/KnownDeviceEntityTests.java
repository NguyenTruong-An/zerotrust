package com.zerotrust.risk.entity;

import com.zerotrust.risk.exception.DeviceTrustRejectedException;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KnownDeviceEntityTests {

    private static final String SUBJECT_ID = "keycloak-user-id";
    private static final String FINGERPRINT_HASH = "a".repeat(64);
    private static final Instant FIRST_SEEN_AT = Instant.parse("2026-09-14T01:00:00Z");

    @Test
    void repeatedTrustPreservesTheOriginalTrustTimeAndAdvancesLastSeen() {
        KnownDeviceEntity device = newDevice();
        Instant firstTrust = FIRST_SEEN_AT.plusSeconds(60);
        Instant repeatedTrust = FIRST_SEEN_AT.plusSeconds(120);

        device.trust(firstTrust);
        device.trust(repeatedTrust);

        assertThat(device.getStatus()).isEqualTo(DeviceStatus.TRUSTED);
        assertThat(device.getTrustedAt()).isEqualTo(firstTrust);
        assertThat(device.getLastSeenAt()).isEqualTo(repeatedTrust);
        assertThat(device.getRevokedAt()).isNull();
    }

    @Test
    void revokedDeviceCannotBeTrustedAgain() {
        KnownDeviceEntity device = newDevice();
        Instant revokedAt = FIRST_SEEN_AT.plusSeconds(60);
        device.revoke(revokedAt);

        assertThatThrownBy(() -> device.trust(revokedAt.plusSeconds(60)))
                .isInstanceOf(DeviceTrustRejectedException.class)
                .hasMessage("revoked device cannot be trusted");
        assertThat(device.getStatus()).isEqualTo(DeviceStatus.REVOKED);
        assertThat(device.getRevokedAt()).isEqualTo(revokedAt);
        assertThat(device.getTrustedAt()).isNull();
    }

    @Test
    void repeatedRevokePreservesTheOriginalRevocationTimeAndAdvancesLastSeen() {
        KnownDeviceEntity device = newDevice();
        Instant firstRevoke = FIRST_SEEN_AT.plusSeconds(60);
        Instant repeatedRevoke = FIRST_SEEN_AT.plusSeconds(120);

        device.revoke(firstRevoke);
        device.revoke(repeatedRevoke);

        assertThat(device.getStatus()).isEqualTo(DeviceStatus.REVOKED);
        assertThat(device.getRevokedAt()).isEqualTo(firstRevoke);
        assertThat(device.getLastSeenAt()).isEqualTo(repeatedRevoke);
    }

    @Test
    void lifecycleEventsCannotPredateTheFirstObservation() {
        KnownDeviceEntity device = newDevice();
        Instant invalidTimestamp = FIRST_SEEN_AT.minusSeconds(1);

        assertThatThrownBy(() -> device.trust(invalidTimestamp))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("trustedAt must not be before firstSeenAt");
        assertThatThrownBy(() -> device.revoke(invalidTimestamp))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("revokedAt must not be before firstSeenAt");
        assertThat(device.getStatus()).isEqualTo(DeviceStatus.PENDING);
        assertThat(device.getLastSeenAt()).isEqualTo(FIRST_SEEN_AT);
    }

    private KnownDeviceEntity newDevice() {
        return new KnownDeviceEntity(SUBJECT_ID, FINGERPRINT_HASH, FIRST_SEEN_AT);
    }
}
