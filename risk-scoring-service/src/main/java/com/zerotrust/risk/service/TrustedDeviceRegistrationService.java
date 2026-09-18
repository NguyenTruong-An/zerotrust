package com.zerotrust.risk.service;

import com.zerotrust.risk.entity.KnownDeviceEntity;
import com.zerotrust.risk.repository.KnownDeviceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class TrustedDeviceRegistrationService {

    private final DeviceFingerprintHasher fingerprintHasher;
    private final KnownDeviceRepository knownDeviceRepository;
    private final Clock clock;

    /**
     * Registers a device only after the trusted Keycloak caller has completed MFA.
     * The raw device identifier is used for HMAC calculation and is never persisted.
     */
    @Transactional
    public void trustAfterMfa(String subjectId, String deviceId) {
        String fingerprintHash = fingerprintHasher.hash(subjectId, deviceId);
        String normalizedSubjectId = subjectId.trim();
        Instant trustedAt = clock.instant();

        knownDeviceRepository
                .findBySubjectIdAndDeviceFingerprintHash(normalizedSubjectId, fingerprintHash)
                .ifPresentOrElse(
                        device -> device.trust(trustedAt),
                        () -> createTrustedDevice(normalizedSubjectId, fingerprintHash, trustedAt)
                );
    }

    private void createTrustedDevice(String subjectId, String fingerprintHash, Instant trustedAt) {
        KnownDeviceEntity device = new KnownDeviceEntity(subjectId, fingerprintHash, trustedAt);
        device.trust(trustedAt);
        knownDeviceRepository.save(device);
    }
}
