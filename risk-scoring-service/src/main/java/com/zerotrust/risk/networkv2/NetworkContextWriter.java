package com.zerotrust.risk.networkv2;

import com.zerotrust.risk.domain.DeviceTrustTimestamp;
import com.zerotrust.risk.domain.SubjectIdentifierNormalizer;
import com.zerotrust.risk.service.AuthenticationHistoryKeyHasher;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import javax.sql.DataSource;
import java.time.Clock;
import java.time.Instant;
import java.util.List;

@Service
public class NetworkContextWriter {
    public enum Outcome { RECORDED, ALREADY_RECORDED, CORRELATION_MISMATCH, EVENT_MISMATCH, GENERATION_OR_PENDING_RESET, NO_PUBLIC_CONTEXT, CLOCK_BOUNDS }
    private final JdbcTemplate jdbc;
    private final NetworkContextRepository repository;
    private final Clock clock;
    private final AuthenticationHistoryKeyHasher hasher;

    public NetworkContextWriter(DataSource dataSource, NetworkContextRepository repository, Clock clock,
                                AuthenticationHistoryKeyHasher hasher) {
        this.jdbc = new JdbcTemplate(dataSource);
        this.jdbc.setQueryTimeout(2);
        this.repository = repository; this.clock = clock;
        this.hasher = hasher;
    }

    /** Parent authentication success has committed before this independent shadow transaction. */
    @Transactional(propagation = Propagation.REQUIRES_NEW, timeout = 5)
    public Outcome learn(String eventId, String subjectId, String clientId, Instant authenticatedAt,
                         PendingNetworkObservations.Pending pending) {
        Instant now = clock.instant();
        if (!pending.subjectHash().equals(hasher.hash("network-v2-subject", SubjectIdentifierNormalizer.normalize(subjectId)))
                || !pending.clientId().equals(clientId)) return Outcome.CORRELATION_MISMATCH;
        if (pending.observation().networkHash() == null) return Outcome.NO_PUBLIC_CONTEXT;
        if (authenticatedAt.isAfter(now.plusSeconds(30)) || authenticatedAt.isBefore(pending.observedAt().minusSeconds(30))) {
            return Outcome.CLOCK_BOUNDS;
        }
        List<Boolean> owners = jdbc.query("""
                SELECT subject_id, client_id, authenticated_at FROM authentication_success_events WHERE event_id = ?
                """, (row, i) -> subjectId.equals(row.getString(1)) && clientId.equals(row.getString(2))
                        && DeviceTrustTimestamp.canonical(authenticatedAt).equals(row.getTimestamp(3).toInstant()), eventId);
        if (owners.size() != 1 || !owners.get(0)) return Outcome.EVENT_MISMATCH;
        // Read/lock an existing generation row; never create state, clear pending, or change generation.
        List<Boolean> current = jdbc.query("""
                SELECT generation, pending_operation_id FROM subject_device_trust WHERE subject_id = ? FOR UPDATE
                """, (row, i) -> row.getLong(1) == pending.generation() && row.getString(2) == null, subjectId);
        if (current.size() != 1 || !current.get(0)) return Outcome.GENERATION_OR_PENDING_RESET;
        if (repository.existsById(eventId)) return Outcome.ALREADY_RECORDED;
        repository.saveAndFlush(new NetworkAuthenticationContextEntity(eventId, pending.subjectHash(), clientId,
                pending.observation(), DeviceTrustTimestamp.canonical(authenticatedAt), now));
        return Outcome.RECORDED;
    }
}
