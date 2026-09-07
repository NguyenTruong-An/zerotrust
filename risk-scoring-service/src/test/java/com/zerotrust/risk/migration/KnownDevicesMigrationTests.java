package com.zerotrust.risk.migration;

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
class KnownDevicesMigrationTests {

    private static final String SUBJECT_ID = "keycloak-user-id";
    private static final String FINGERPRINT_HASH = "a".repeat(64);

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void createsKnownDevicesTableWithExpectedColumns() {
        insertKnownDevice(SUBJECT_ID, FINGERPRINT_HASH);

        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM known_devices WHERE subject_id = ? AND status = ?",
                Integer.class,
                SUBJECT_ID,
                "TRUSTED"
        );

        assertThat(count).isEqualTo(1);
    }

    @Test
    void preventsDuplicateFingerprintForTheSameSubject() {
        insertKnownDevice(SUBJECT_ID, FINGERPRINT_HASH);

        assertThatThrownBy(() -> insertKnownDevice(SUBJECT_ID, FINGERPRINT_HASH))
                .isInstanceOf(DataAccessException.class);
    }

    private void insertKnownDevice(String subjectId, String fingerprintHash) {
        Timestamp now = Timestamp.from(Instant.parse("2026-09-06T08:00:00Z"));
        jdbcTemplate.update(
                """
                INSERT INTO known_devices (
                    subject_id,
                    device_fingerprint_hash,
                    status,
                    first_seen_at,
                    last_seen_at,
                    trusted_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                subjectId,
                fingerprintHash,
                "TRUSTED",
                now,
                now,
                now
        );
    }
}
