package com.zerotrust.risk.repository;

import com.zerotrust.risk.entity.DeviceStatus;
import com.zerotrust.risk.entity.KnownDeviceEntity;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@ActiveProfiles("test")
class KnownDeviceRepositoryTests {

    private static final String SUBJECT_ID = "keycloak-user-id";
    private static final String FINGERPRINT_HASH = "b".repeat(64);
    private static final Instant FIRST_SEEN_AT = Instant.parse("2026-09-07T01:00:00Z");

    @Autowired
    private KnownDeviceRepository repository;

    @Test
    void savesAndFindsDeviceBySubjectAndFingerprint() {
        KnownDeviceEntity saved = repository.saveAndFlush(
                new KnownDeviceEntity(SUBJECT_ID, FINGERPRINT_HASH, FIRST_SEEN_AT)
        );

        Optional<KnownDeviceEntity> found = repository.findBySubjectIdAndDeviceFingerprintHash(
                SUBJECT_ID,
                FINGERPRINT_HASH
        );

        assertThat(saved.getId()).isNotNull();
        assertThat(found).isPresent();
        assertThat(found.orElseThrow().getStatus()).isEqualTo(DeviceStatus.PENDING);
        assertThat(found.orElseThrow().getFirstSeenAt()).isEqualTo(FIRST_SEEN_AT);
    }

    @Test
    void identifiesTrustedDevice() {
        KnownDeviceEntity device = new KnownDeviceEntity(
                SUBJECT_ID,
                FINGERPRINT_HASH,
                FIRST_SEEN_AT
        );
        device.trust(FIRST_SEEN_AT.plusSeconds(60));
        repository.saveAndFlush(device);

        boolean trusted = repository.existsBySubjectIdAndDeviceFingerprintHashAndStatus(
                SUBJECT_ID,
                FINGERPRINT_HASH,
                DeviceStatus.TRUSTED
        );

        assertThat(trusted).isTrue();
    }

    @Test
    void revokedDeviceIsNotTreatedAsTrusted() {
        KnownDeviceEntity device = new KnownDeviceEntity(
                SUBJECT_ID,
                FINGERPRINT_HASH,
                FIRST_SEEN_AT
        );
        device.trust(FIRST_SEEN_AT.plusSeconds(60));
        device.revoke(FIRST_SEEN_AT.plusSeconds(120));
        repository.saveAndFlush(device);

        boolean trusted = repository.existsBySubjectIdAndDeviceFingerprintHashAndStatus(
                SUBJECT_ID,
                FINGERPRINT_HASH,
                DeviceStatus.TRUSTED
        );

        assertThat(trusted).isFalse();
        assertThat(device.getStatus()).isEqualTo(DeviceStatus.REVOKED);
        assertThat(device.getRevokedAt()).isEqualTo(FIRST_SEEN_AT.plusSeconds(120));
    }
}
