package com.zerotrust.risk.service;

import com.zerotrust.risk.domain.SubjectIdentifierNormalizer;
import com.zerotrust.risk.domain.DeviceTrustTimestamp;
import com.zerotrust.risk.entity.KnownDeviceEntity;
import com.zerotrust.risk.entity.DeviceStatus;
import com.zerotrust.risk.exception.DeviceTrustRejectedException;
import com.zerotrust.risk.repository.KnownDeviceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.annotation.Propagation;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class DeviceTrustLifecycle {
    private final JdbcTemplate jdbc;
    private final KnownDeviceRepository devices;
    private final Clock clock;

    @Transactional
    public long generation(String subjectId) {
        subjectId = SubjectIdentifierNormalizer.normalize(subjectId);
        return lockGeneration(subjectId);
    }

    public record Snapshot(long generation, boolean resetPending) {}

    @Transactional
    public Snapshot snapshot(String subjectId) {
        subjectId = SubjectIdentifierNormalizer.normalize(subjectId);
        long generation = lockGeneration(subjectId);
        return new Snapshot(generation, pending(subjectId) != null);
    }

    // Caller must retain this subject lock until device registration commits.
    @Transactional(propagation = Propagation.MANDATORY)
    public void requireGeneration(String subjectId, long expected) {
        subjectId = SubjectIdentifierNormalizer.normalize(subjectId);
        if (expected < 0 || lockGeneration(subjectId) != expected || pending(subjectId) != null) {
            throw new DeviceTrustRejectedException();
        }
    }

    @Transactional
    public void revoke(String subjectId, UUID operationId, String requestedBy) {
        subjectId = SubjectIdentifierNormalizer.normalize(subjectId);
        long generation = lockGeneration(subjectId);
        var previous = jdbc.queryForList(
                "SELECT subject_id, requested_by FROM device_trust_revocations WHERE operation_id = ?",
                operationId.toString());
        if (!previous.isEmpty()) {
            var row = previous.get(0);
            if (!subjectId.equals(row.get("subject_id")) || !requestedBy.equals(row.get("requested_by"))) {
                throw new DeviceTrustRejectedException();
            }
            return;
        }
        long next = Math.addExact(generation, 1);
        jdbc.update("UPDATE subject_device_trust SET generation = ?, pending_operation_id = ? WHERE subject_id = ?",
                next, operationId.toString(), subjectId);
        Instant now = DeviceTrustTimestamp.canonical(clock.instant());
        int count = 0;
        for (KnownDeviceEntity device : devices.findCurrentForRevocation(subjectId)) {
            if (device.getStatus() != DeviceStatus.REVOKED) {
                device.revokeForMfaReset(now);
                count++;
            }
        }
        devices.flush();
        jdbc.update("""
                INSERT INTO device_trust_revocations
                    (operation_id, subject_id, requested_by, generation, revoked_count, revoked_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """, operationId.toString(), subjectId, requestedBy, next, count, Timestamp.from(now));
    }

    @Transactional
    public void complete(String subjectId, UUID operationId, String requestedBy) {
        subjectId = SubjectIdentifierNormalizer.normalize(subjectId);
        lockGeneration(subjectId);
        var rows = jdbc.queryForList("SELECT subject_id, requested_by, completed_at FROM device_trust_revocations WHERE operation_id = ?",
                operationId.toString());
        if (rows.isEmpty()
                || !subjectId.equals(rows.get(0).get("subject_id"))
                || !requestedBy.equals(rows.get(0).get("requested_by"))) {
            throw new DeviceTrustRejectedException();
        }
        if (rows.get(0).get("completed_at") != null) return;
        if (!operationId.toString().equals(pending(subjectId))) throw new DeviceTrustRejectedException();
        jdbc.update("UPDATE subject_device_trust SET pending_operation_id = NULL WHERE subject_id = ?", subjectId);
        jdbc.update("UPDATE device_trust_revocations SET completed_at = ? WHERE operation_id = ?",
                Timestamp.from(DeviceTrustTimestamp.canonical(clock.instant())), operationId.toString());
    }

    private String pending(String subjectId) {
        return jdbc.queryForObject("SELECT pending_operation_id FROM subject_device_trust WHERE subject_id = ?",
                String.class, subjectId);
    }

    private long lockGeneration(String subjectId) {
        jdbc.update("INSERT IGNORE INTO subject_device_trust (subject_id, generation) VALUES (?, 0)", subjectId);
        return jdbc.queryForObject("SELECT generation FROM subject_device_trust WHERE subject_id = ? FOR UPDATE",
                Long.class, subjectId);
    }
}
