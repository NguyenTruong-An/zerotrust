package com.zerotrust.risk.repository;

import com.zerotrust.risk.entity.AuthenticationSuccessEventEntity;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@ActiveProfiles("test")
class AuthenticationSuccessEventRepositoryTests {

    @Autowired
    private AuthenticationSuccessEventRepository repository;

    @Test
    void returnsOnlyPriorEventsForTheRequestedSubjectClientAndWindow() {
        Instant evaluationTime = Instant.parse("2026-09-18T10:00:00Z");
        save("event-1", "subject-1", "zerotrust-spa", "2026-09-18T07:00:00Z");
        save("event-2", "subject-1", "zerotrust-spa", "2026-09-18T08:00:00Z");
        save("event-3", "subject-1", "zerotrust-spa", "2026-09-18T09:00:00Z");
        save("other-subject", "subject-2", "zerotrust-spa", "2026-09-18T09:30:00Z");
        save("other-client", "subject-1", "other-client", "2026-09-18T09:30:00Z");
        save("outside-window", "subject-1", "zerotrust-spa", "2026-09-17T23:59:59Z");
        save("at-upper-bound", "subject-1", "zerotrust-spa", "2026-09-18T10:00:00Z");

        List<Instant> result = repository.findRecentAuthenticationTimes(
                "subject-1",
                "zerotrust-spa",
                Instant.parse("2026-09-18T00:00:00Z"),
                evaluationTime,
                PageRequest.of(0, 2)
        );

        assertThat(result).containsExactly(
                Instant.parse("2026-09-18T09:00:00Z"),
                Instant.parse("2026-09-18T08:00:00Z")
        );
    }

    private void save(String eventId, String subjectId, String clientId, String authenticatedAt) {
        Instant eventTime = Instant.parse(authenticatedAt);
        repository.saveAndFlush(new AuthenticationSuccessEventEntity(
                eventId,
                subjectId,
                clientId,
                eventTime,
                eventTime.plusSeconds(1)
        ));
    }
}
