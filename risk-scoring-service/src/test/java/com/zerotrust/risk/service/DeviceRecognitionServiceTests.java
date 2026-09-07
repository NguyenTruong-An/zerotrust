package com.zerotrust.risk.service;

import com.zerotrust.risk.config.DeviceFingerprintProperties;
import com.zerotrust.risk.domain.DeviceRecognition;
import com.zerotrust.risk.domain.DeviceRecognitionStatus;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.entity.KnownDeviceEntity;
import com.zerotrust.risk.repository.KnownDeviceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeviceRecognitionServiceTests {

    private static final String SUBJECT_ID = "subject-1";
    private static final String DEVICE_ID = "device-1";
    private static final Instant NOW = Instant.parse("2026-09-07T01:00:00Z");

    @Mock
    private KnownDeviceRepository repository;

    private DeviceFingerprintHasher hasher;
    private DeviceRecognitionService service;

    @BeforeEach
    void setUp() {
        DeviceFingerprintProperties properties = new DeviceFingerprintProperties();
        properties.setPepper("test-only-device-fingerprint-pepper-value");
        hasher = new DeviceFingerprintHasher(properties);
        service = new DeviceRecognitionService(hasher, repository);
    }

    @Test
    void reportsMissingWithoutQueryingDatabase() {
        DeviceRecognition result = service.recognize(context(null));

        assertThat(result.status()).isEqualTo(DeviceRecognitionStatus.MISSING);
        assertThat(result.fingerprintHash()).isNull();
        verifyNoInteractions(repository);
    }

    @Test
    void reportsNewWhenFingerprintIsNotStored() {
        String hash = hasher.hash(SUBJECT_ID, DEVICE_ID);
        when(repository.findBySubjectIdAndDeviceFingerprintHash(SUBJECT_ID, hash))
                .thenReturn(Optional.empty());

        DeviceRecognition result = service.recognize(context(DEVICE_ID));

        assertThat(result.status()).isEqualTo(DeviceRecognitionStatus.NEW);
        assertThat(result.fingerprintHash()).isEqualTo(hash);
    }

    @Test
    void reportsTrustedStoredDevice() {
        String hash = hasher.hash(SUBJECT_ID, DEVICE_ID);
        KnownDeviceEntity device = new KnownDeviceEntity(SUBJECT_ID, hash, NOW);
        device.trust(NOW.plusSeconds(60));
        when(repository.findBySubjectIdAndDeviceFingerprintHash(SUBJECT_ID, hash))
                .thenReturn(Optional.of(device));

        DeviceRecognition result = service.recognize(context(DEVICE_ID));

        assertThat(result.status()).isEqualTo(DeviceRecognitionStatus.TRUSTED);
    }

    @Test
    void reportsRevokedStoredDevice() {
        String hash = hasher.hash(SUBJECT_ID, DEVICE_ID);
        KnownDeviceEntity device = new KnownDeviceEntity(SUBJECT_ID, hash, NOW);
        device.revoke(NOW.plusSeconds(60));
        when(repository.findBySubjectIdAndDeviceFingerprintHash(SUBJECT_ID, hash))
                .thenReturn(Optional.of(device));

        DeviceRecognition result = service.recognize(context(DEVICE_ID));

        assertThat(result.status()).isEqualTo(DeviceRecognitionStatus.REVOKED);
    }

    private LoginContext context(String deviceId) {
        return new LoginContext(
                SUBJECT_ID,
                "authentication-session-id",
                "zerotrust-spa",
                "203.0.113.10",
                "Mozilla/5.0",
                deviceId,
                NOW
        );
    }
}
