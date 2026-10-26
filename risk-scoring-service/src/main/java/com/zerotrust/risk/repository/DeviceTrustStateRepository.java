package com.zerotrust.risk.repository;

import com.zerotrust.risk.domain.DeviceTrustTimestamp;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
@Transactional(propagation = Propagation.MANDATORY)
public class DeviceTrustStateRepository {

    private final JdbcTemplate jdbc;

    public SubjectState lockSubject(String subjectId) {
        jdbc.update("INSERT IGNORE INTO subject_device_trust (subject_id, generation) VALUES (?, 0)", subjectId);
        return jdbc.queryForObject("""
                SELECT generation, pending_operation_id
                FROM subject_device_trust WHERE subject_id = ? FOR UPDATE
                """, (row, index) -> new SubjectState(row.getLong("generation"), row.getString("pending_operation_id")),
                subjectId);
    }

    public Optional<Revocation> findRevocation(UUID operationId) {
        return jdbc.query("""
                SELECT subject_id, requested_by, completed_at
                FROM device_trust_revocations WHERE operation_id = ?
                """, (row, index) -> new Revocation(row.getString("subject_id"), row.getString("requested_by"),
                row.getTimestamp("completed_at") != null), operationId.toString()).stream().findFirst();
    }

    public void markPending(String subjectId, long generation, UUID operationId) {
        jdbc.update("""
                UPDATE subject_device_trust SET generation = ?, pending_operation_id = ? WHERE subject_id = ?
                """, generation, operationId.toString(), subjectId);
    }

    public void recordRevocation(UUID operationId, String subjectId, String requestedBy,
                                 long generation, int revokedCount, Instant revokedAt) {
        jdbc.update("""
                INSERT INTO device_trust_revocations
                    (operation_id, subject_id, requested_by, generation, revoked_count, revoked_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """, operationId.toString(), subjectId, requestedBy, generation, revokedCount, Timestamp.from(DeviceTrustTimestamp.canonical(revokedAt)));
    }

    public void markCompleted(String subjectId, UUID operationId, Instant completedAt) {
        jdbc.update("UPDATE subject_device_trust SET pending_operation_id = NULL WHERE subject_id = ?", subjectId);
        jdbc.update("UPDATE device_trust_revocations SET completed_at = ? WHERE operation_id = ?",
                Timestamp.from(DeviceTrustTimestamp.canonical(completedAt)), operationId.toString());
    }

    public record SubjectState(long generation, String pendingOperationId) {
        public boolean resetPending() {
            return pendingOperationId != null;
        }
    }

    public record Revocation(String subjectId, String requestedBy, boolean completed) {
        public boolean belongsTo(String subject, String requester) {
            return subjectId.equals(subject) && requestedBy.equals(requester);
        }
    }
}
