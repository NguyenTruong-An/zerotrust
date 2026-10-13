package com.zerotrust.risk.repository;

import com.zerotrust.risk.entity.KnownDeviceEntity;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@RequiredArgsConstructor
public class KnownDeviceRevocationRepositoryImpl implements KnownDeviceRevocationRepository {
    private final EntityManager entityManager;

    /** Caller holds the subject guard until commit; revocation must see rows newer than its RR snapshot. */
    @Override
    @Transactional(propagation = Propagation.MANDATORY)
    @SuppressWarnings("unchecked")
    public List<KnownDeviceEntity> findCurrentForRevocation(String subjectId) {
        // Preserve pending caller changes before refreshing any managed device.
        entityManager.flush();
        List<KnownDeviceEntity> devices = entityManager.createNativeQuery("""
                SELECT d.* FROM known_devices d
                WHERE d.subject_id = :subjectId ORDER BY d.id FOR UPDATE
                """, KnownDeviceEntity.class).setParameter("subjectId", subjectId).getResultList();
        // A locking SQL result can still resolve to an older entity in the first-level cache.
        for (KnownDeviceEntity device : devices) {
            entityManager.refresh(device, LockModeType.PESSIMISTIC_WRITE);
        }
        return devices;
    }
}
