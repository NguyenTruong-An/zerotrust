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
                .map(KnownDeviceEntity::getStatus)
                .map(this::toRecognitionStatus)
                .orElse(DeviceRecognitionStatus.NEW);

        return new DeviceRecognition(status, fingerprintHash);
    }

    private DeviceRecognitionStatus toRecognitionStatus(DeviceStatus status) {
        return switch (status) {
            case PENDING -> DeviceRecognitionStatus.PENDING;
            case TRUSTED -> DeviceRecognitionStatus.TRUSTED;
            case REVOKED -> DeviceRecognitionStatus.REVOKED;
        };
    }
}
