package com.zerotrust.risk.service;

import com.zerotrust.risk.config.DeviceFingerprintProperties;
import com.zerotrust.risk.entity.DeviceStatus;
import com.zerotrust.risk.entity.KnownDeviceEntity;
import com.zerotrust.risk.exception.DeviceTrustRejectedException;
import com.zerotrust.risk.repository.KnownDeviceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DataJpaTest
@ActiveProfiles("test")
class TrustedDeviceRegistrationServiceTests {

    private static final String SUBJECT_ID = "keycloak-user-id";
    private static final String DEVICE_ID = "secure-random-device-identifier";
    private static final Instant FIRST_MFA_AT = Instant.parse("2026-09-14T02:00:00Z");

    @Autowired
    private KnownDeviceRepository repository;

    private DeviceFingerprintHasher fingerprintHasher;

    @BeforeEach
    void setUp() {
        DeviceFingerprintProperties properties = new DeviceFingerprintProperties();
        properties.setPepper("test-only-device-fingerprint-pepper-value");
        fingerprintHasher = new DeviceFingerprintHasher(properties);
    }

    @Test
    void registersANewTrustedDeviceWithoutPersistingTheRawIdentifier() {
        serviceAt(FIRST_MFA_AT).trustAfterMfa(SUBJECT_ID, DEVICE_ID);
        repository.flush();

        KnownDeviceEntity stored = findDevice();
        assertThat(stored.getStatus()).isEqualTo(DeviceStatus.TRUSTED);
        assertThat(stored.getFirstSeenAt()).isEqualTo(FIRST_MFA_AT);
        assertThat(stored.getTrustedAt()).isEqualTo(FIRST_MFA_AT);
        assertThat(stored.getLastSeenAt()).isEqualTo(FIRST_MFA_AT);
        assertThat(stored.getDeviceFingerprintHash()).hasSize(64).doesNotContain(DEVICE_ID);
    }

    @Test
    void repeatedRegistrationKeepsOneDeviceAndPreservesTheOriginalTrustTime() {
        Instant repeatedAt = FIRST_MFA_AT.plusSeconds(60);

        serviceAt(FIRST_MFA_AT).trustAfterMfa(SUBJECT_ID, DEVICE_ID);
        repository.flush();
        serviceAt(repeatedAt).trustAfterMfa(SUBJECT_ID, DEVICE_ID);
        repository.flush();

        KnownDeviceEntity stored = findDevice();
        assertThat(repository.count()).isOne();
        assertThat(stored.getTrustedAt()).isEqualTo(FIRST_MFA_AT);
        assertThat(stored.getLastSeenAt()).isEqualTo(repeatedAt);
    }

    @Test
    void refusesToTrustARevokedDeviceIdentifier() {
        serviceAt(FIRST_MFA_AT).trustAfterMfa(SUBJECT_ID, DEVICE_ID);
        KnownDeviceEntity device = findDevice();
        Instant revokedAt = FIRST_MFA_AT.plusSeconds(60);
        device.revoke(revokedAt);
        repository.flush();

        assertThatThrownBy(() -> serviceAt(revokedAt.plusSeconds(60))
                .trustAfterMfa(SUBJECT_ID, DEVICE_ID))
                .isInstanceOf(DeviceTrustRejectedException.class)
                .hasMessage("revoked device cannot be trusted");
        assertThat(device.getStatus()).isEqualTo(DeviceStatus.REVOKED);
        assertThat(device.getRevokedAt()).isEqualTo(revokedAt);
    }

    private KnownDeviceEntity findDevice() {
        String fingerprintHash = fingerprintHasher.hash(SUBJECT_ID, DEVICE_ID);
        return repository.findBySubjectIdAndDeviceFingerprintHash(SUBJECT_ID, fingerprintHash)
                .orElseThrow();
    }

    private TrustedDeviceRegistrationService serviceAt(Instant instant) {
        Clock clock = Clock.fixed(instant, ZoneOffset.UTC);
        return new TrustedDeviceRegistrationService(fingerprintHasher, repository, clock);
    }
}
