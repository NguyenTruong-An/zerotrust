package com.zerotrust.risk.service;

import com.zerotrust.risk.repository.AuthenticationSuccessEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationSuccessServiceTests {

    private static final Instant AUTHENTICATED_AT = Instant.parse("2026-09-17T03:00:00Z");
    private static final Instant RECORDED_AT = Instant.parse("2026-09-17T03:00:01Z");

    @Mock
    private AuthenticationSuccessEventRepository eventRepository;

    private AuthenticationSuccessService service;

    @BeforeEach
    void setUp() {
        service = new AuthenticationSuccessService(
                eventRepository,
                Clock.fixed(RECORDED_AT, ZoneOffset.UTC)
        );
    }

    @Test
    void storesNormalizedSuccessfulLoginWithRiskServiceTimestamp() {
        when(eventRepository.insertIfAbsent(
                "event-1",
                "subject-1",
                "zerotrust-spa",
                AUTHENTICATED_AT,
                RECORDED_AT
        )).thenReturn(1);

        boolean recorded = service.recordSuccess(
                " event-1 ",
                " subject-1 ",
                " zerotrust-spa ",
                AUTHENTICATED_AT
        );

        assertThat(recorded).isTrue();
        verify(eventRepository).insertIfAbsent(
                "event-1",
                "subject-1",
                "zerotrust-spa",
                AUTHENTICATED_AT,
                RECORDED_AT
        );
    }

    @Test
    void treatsAnExistingEventIdAsAnIdempotentReplay() {
        when(eventRepository.insertIfAbsent(
                "event-1",
                "subject-1",
                "zerotrust-spa",
                AUTHENTICATED_AT,
                RECORDED_AT
        )).thenReturn(0);

        boolean recorded = service.recordSuccess(
                "event-1",
                "subject-1",
                "zerotrust-spa",
                AUTHENTICATED_AT
        );

        assertThat(recorded).isFalse();
    }
}
