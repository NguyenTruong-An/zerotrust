package com.zerotrust.risk.networkv2;

import com.zerotrust.risk.domain.DeviceTrustTimestamp;
import com.zerotrust.risk.repository.AuthenticationFailureStore;
import com.zerotrust.risk.service.AuthenticationSuccessService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import java.sql.Timestamp;
import java.time.*;
import java.util.UUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Isolated in-memory H2/MySQL-mode schema. No developer MySQL or Redis connection. */
@SpringBootTest
@ActiveProfiles("test")
class NetworkRiskV2IntegrationTests {
    @MockitoBean AuthenticationFailureStore failureStore;
    @Autowired JdbcTemplate jdbc;
    @Autowired NetworkContextWriter writer;
    @Autowired NetworkContextRepository repository;
    @Autowired AuthenticationSuccessService successes;
    @Autowired com.zerotrust.risk.service.AuthenticationHistoryKeyHasher hasher;
    private record Fixture(String event, String subject, Instant at, PendingNetworkObservations.Pending pending) {}
    private Fixture fixture() {
        String id = UUID.randomUUID().toString();
        Instant at = DeviceTrustTimestamp.canonical(Instant.now());
        var pending = new PendingNetworkObservations.Pending(hasher.hash("network-v2-subject", id), "zerotrust-spa",
                new NetworkObservation("VN", 100L, "b".repeat(64), 20, NetworkObservation.Quality.COUNTRY_ASN), at, 7);
        jdbc.update("INSERT INTO subject_device_trust(subject_id, generation) VALUES (?, 7)", id);
        assertThat(successes.recordSuccess(id, id, "zerotrust-spa", at)).isTrue();
        return new Fixture(id, id, at, pending);
    }
    private NetworkContextWriter.Outcome learn(Fixture fixture) {
        return writer.learn(fixture.event(), fixture.subject(), "zerotrust-spa", fixture.at(), fixture.pending());
    }
    @Test void migrationsPreserveV5AndNewHistoryIsPersistedWithIdempotentParentLink() {
        assertThat(jdbc.getDataSource()).isNotNull();
        assertThat(jdbc.queryForObject("SELECT checksum FROM flyway_schema_history WHERE version = '5'", Integer.class)).isEqualTo(661092940);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM flyway_schema_history WHERE version = '6' AND success = TRUE", Integer.class)).isEqualTo(1);
        var fixture = fixture();
        assertThat(learn(fixture)).isEqualTo(NetworkContextWriter.Outcome.RECORDED);
        assertThat(learn(fixture)).isEqualTo(NetworkContextWriter.Outcome.ALREADY_RECORDED);
        assertThat(repository.findById(fixture.event()).orElseThrow().getSubjectHash()).isEqualTo(fixture.pending().subjectHash());
        assertThat(successes.recordSuccess(fixture.event(), "other", "other", fixture.at())).isFalse();
        assertThat(jdbc.queryForObject("SELECT generation FROM subject_device_trust WHERE subject_id=?", Long.class, fixture.subject())).isEqualTo(7);
    }
    @Test void wrongSubjectClientOrEventTimeCannotPoisonHistory() {
        var fixture = fixture();
        assertThat(writer.learn(fixture.event(), "other", "zerotrust-spa", fixture.at(), fixture.pending()))
                .isEqualTo(NetworkContextWriter.Outcome.CORRELATION_MISMATCH);
        assertThat(writer.learn(fixture.event(), fixture.subject(), "other-client", fixture.at(), fixture.pending()))
                .isEqualTo(NetworkContextWriter.Outcome.CORRELATION_MISMATCH);
        assertThat(writer.learn(fixture.event(), fixture.subject(), "zerotrust-spa", fixture.at().plusSeconds(1), fixture.pending()))
                .isEqualTo(NetworkContextWriter.Outcome.EVENT_MISMATCH);
        assertThat(repository.existsById(fixture.event())).isFalse();
    }
    @Test void generationAdvanceAndPendingResetFenceLearningWithoutMutatingTrust() {
        var fixture = fixture();
        jdbc.update("UPDATE subject_device_trust SET generation=8 WHERE subject_id=?", fixture.subject());
        assertThat(learn(fixture)).isEqualTo(NetworkContextWriter.Outcome.GENERATION_OR_PENDING_RESET);
        jdbc.update("UPDATE subject_device_trust SET generation=7,pending_operation_id=? WHERE subject_id=?", UUID.randomUUID().toString(), fixture.subject());
        assertThat(learn(fixture)).isEqualTo(NetworkContextWriter.Outcome.GENERATION_OR_PENDING_RESET);
        assertThat(jdbc.queryForObject("SELECT pending_operation_id FROM subject_device_trust WHERE subject_id=?", String.class, fixture.subject())).isNotBlank();
        assertThat(repository.existsById(fixture.event())).isFalse();
    }
    @Test void unverifiedOrMissingGenerationStateCannotCreateTrustedHistory() {
        var fixture = fixture();
        assertThat(writer.learn("unverified-event", fixture.subject(), "zerotrust-spa", fixture.at(), fixture.pending()))
                .isEqualTo(NetworkContextWriter.Outcome.EVENT_MISMATCH);
        jdbc.update("DELETE FROM subject_device_trust WHERE subject_id=?", fixture.subject());
        assertThat(learn(fixture)).isEqualTo(NetworkContextWriter.Outcome.GENERATION_OR_PENDING_RESET);
        assertThat(repository.existsById(fixture.event())).isFalse();
    }
    @Test void databaseRejectsHistoryWithoutVerifiedAuthenticationParent() {
        var fixture = fixture();
        assertThatThrownBy(() -> repository.saveAndFlush(new NetworkAuthenticationContextEntity(UUID.randomUUID().toString(),
                "a".repeat(64), "zerotrust-spa", fixture.pending().observation(), fixture.at(), fixture.at())))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
    }
    @Test void oldOrFutureSuccessTimestampsAreNotLearningEvidence() {
        var fixture = fixture();
        assertThat(writer.learn(fixture.event(), fixture.subject(), "zerotrust-spa", fixture.at().minusSeconds(31), fixture.pending()))
                .isEqualTo(NetworkContextWriter.Outcome.CLOCK_BOUNDS);
        assertThat(writer.learn(fixture.event(), fixture.subject(), "zerotrust-spa", fixture.at().plusSeconds(120), fixture.pending()))
                .isEqualTo(NetworkContextWriter.Outcome.CLOCK_BOUNDS);
    }
}
