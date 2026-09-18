package com.zerotrust.risk.migration;

import com.zerotrust.risk.repository.AuthenticationSuccessEventRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class AuthenticationSuccessEventsMigrationTests {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private AuthenticationSuccessEventRepository eventRepository;

    @Test
    void createsAuthenticationSuccessEventsTableWithExpectedColumns() {
        insert("event-1");

        Integer count = jdbcTemplate.queryForObject(
                """
                SELECT COUNT(*)
                FROM authentication_success_events
                WHERE subject_id = ? AND client_id = ?
                """,
                Integer.class,
                "subject-1",
                "zerotrust-spa"
        );

        assertThat(count).isEqualTo(1);
    }

    @Test
    void preventsDuplicateKeycloakEventIds() {
        insert("event-1");

        assertThatThrownBy(() -> insert("event-1"))
                .isInstanceOf(DataAccessException.class);
    }

    @Test
    void repositoryAtomicallyIgnoresAnIdempotentReplay() {
        Instant authenticatedAt = Instant.parse("2026-09-17T03:00:00Z");
        Instant recordedAt = Instant.parse("2026-09-17T03:00:01Z");

        int firstInsert = eventRepository.insertIfAbsent(
                "event-1",
                "subject-1",
                "zerotrust-spa",
                authenticatedAt,
                recordedAt
        );
        int replay = eventRepository.insertIfAbsent(
                "event-1",
                "subject-1",
                "zerotrust-spa",
                authenticatedAt,
                recordedAt
        );

        assertThat(firstInsert).isEqualTo(1);
        assertThat(replay).isZero();
    }

    private void insert(String eventId) {
        Timestamp authenticatedAt = Timestamp.from(Instant.parse("2026-09-17T03:00:00Z"));
        Timestamp recordedAt = Timestamp.from(Instant.parse("2026-09-17T03:00:01Z"));
        jdbcTemplate.update(
                """
                INSERT INTO authentication_success_events (
                    event_id,
                    subject_id,
                    client_id,
                    authenticated_at,
                    recorded_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                eventId,
                "subject-1",
                "zerotrust-spa",
                authenticatedAt,
                recordedAt
        );
    }
}
