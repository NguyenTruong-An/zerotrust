package com.zerotrust.risk.repository;

import com.zerotrust.risk.entity.DeviceStatus;
import com.zerotrust.risk.entity.KnownDeviceEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface KnownDeviceRepository extends JpaRepository<KnownDeviceEntity, Long> {

    Optional<KnownDeviceEntity> findBySubjectIdAndDeviceFingerprintHash(
            String subjectId,
            String deviceFingerprintHash
    );

    boolean existsBySubjectIdAndDeviceFingerprintHashAndStatus(
            String subjectId,
            String deviceFingerprintHash,
            DeviceStatus status
    );
}
