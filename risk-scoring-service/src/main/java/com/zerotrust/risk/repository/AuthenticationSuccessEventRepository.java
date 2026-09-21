package com.zerotrust.risk.repository;

import com.zerotrust.risk.entity.AuthenticationSuccessEventEntity;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;

public interface AuthenticationSuccessEventRepository
        extends JpaRepository<AuthenticationSuccessEventEntity, Long> {

    @Modifying
    @Query(
            value = """
                    INSERT IGNORE INTO authentication_success_events (
                        event_id,
                        subject_id,
                        client_id,
                        authenticated_at,
                        recorded_at
                    ) VALUES (
                        :eventId,
                        :subjectId,
                        :clientId,
                        :authenticatedAt,
                        :recordedAt
                    )
                    """,
            nativeQuery = true
    )
    int insertIfAbsent(
            @Param("eventId") String eventId,
            @Param("subjectId") String subjectId,
            @Param("clientId") String clientId,
            @Param("authenticatedAt") Instant authenticatedAt,
            @Param("recordedAt") Instant recordedAt
    );

    @Query("""
            SELECT event.authenticatedAt
            FROM AuthenticationSuccessEventEntity event
            WHERE event.subjectId = :subjectId
              AND event.clientId = :clientId
              AND event.authenticatedAt >= :windowStart
              AND event.authenticatedAt < :evaluationTime
            ORDER BY event.authenticatedAt DESC
            """)
    List<Instant> findRecentAuthenticationTimes(
            @Param("subjectId") String subjectId,
            @Param("clientId") String clientId,
            @Param("windowStart") Instant windowStart,
            @Param("evaluationTime") Instant evaluationTime,
            Pageable pageable
    );
}
