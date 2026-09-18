package com.zerotrust.risk.service;

import com.zerotrust.risk.repository.AuthenticationSuccessEventRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class AuthenticationSuccessService {

    private final AuthenticationSuccessEventRepository eventRepository;
    private final Clock clock;

    @Transactional
    public boolean recordSuccess(
            String eventId,
            String subjectId,
            String clientId,
            Instant authenticatedAt
    ) {
        String normalizedEventId = requireText(eventId, "eventId");
        int insertedRows = eventRepository.insertIfAbsent(
                normalizedEventId,
                requireText(subjectId, "subjectId"),
                requireText(clientId, "clientId"),
                Objects.requireNonNull(authenticatedAt, "authenticatedAt must not be null"),
                clock.instant()
        );
        return insertedRows == 1;
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value.trim();
    }
}
