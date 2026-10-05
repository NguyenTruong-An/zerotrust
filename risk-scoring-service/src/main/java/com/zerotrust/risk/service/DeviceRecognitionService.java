package com.zerotrust.risk.service;

import com.zerotrust.risk.domain.DeviceRecognition;
import com.zerotrust.risk.domain.DeviceRecognitionStatus;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.entity.DeviceStatus;
import com.zerotrust.risk.entity.KnownDeviceEntity;
import com.zerotrust.risk.repository.KnownDeviceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class DeviceRecognitionService {

    private final DeviceFingerprintHasher fingerprintHasher;
    private final KnownDeviceRepository knownDeviceRepository;

    @Transactional(readOnly = true)
    public DeviceRecognition recognize(LoginContext context) {
        if (context.deviceId() == null || context.deviceId().isBlank()) {
            return DeviceRecognition.missing();
        }

        String fingerprintHash = fingerprintHasher.hash(context.subjectId(), context.deviceId());
        DeviceRecognitionStatus status = knownDeviceRepository
                .findBySubjectIdAndDeviceFingerprintHash(context.subjectId(), fingerprintHash)
                .map(device -> recognizeStored(device, context.receivedAt()))
                .orElse(DeviceRecognitionStatus.NEW);

        return new DeviceRecognition(status, fingerprintHash);
    }

    private DeviceRecognitionStatus recognizeStored(KnownDeviceEntity device, java.time.Instant now) {
        if (device.getStatus() == DeviceStatus.REVOKED && "MFA_RESET".equals(device.getRevocationReason())) {
            return DeviceRecognitionStatus.REAUTHENTICATION_REQUIRED;
        }
        if (device.getStatus() == DeviceStatus.TRUSTED && (device.getTrustedAt() == null
                || !now.isBefore(device.getTrustedAt().plus(java.time.Duration.ofDays(30))))) {
            return DeviceRecognitionStatus.REAUTHENTICATION_REQUIRED;
        }
        return switch (device.getStatus()) {
            case PENDING -> DeviceRecognitionStatus.PENDING;
            case TRUSTED -> DeviceRecognitionStatus.TRUSTED;
            case REVOKED -> DeviceRecognitionStatus.REVOKED;
        };
    }
}
