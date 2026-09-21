package com.zerotrust.risk.service;

import com.zerotrust.risk.config.TemporalRiskProperties;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.TemporalProfileStatus;
import com.zerotrust.risk.domain.TemporalRiskAssessment;
import com.zerotrust.risk.repository.AuthenticationSuccessEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.data.domain.Pageable;

import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TemporalRiskCalculatorTests {

    private static final Instant EVALUATION_TIME = Instant.parse("2026-09-21T08:00:00Z");

    @Mock
    private AuthenticationSuccessEventRepository eventRepository;

    private TemporalRiskCalculator calculator;
    private LoginContext context;

    @BeforeEach
    void setUp() {
        calculator = new TemporalRiskCalculator(eventRepository, properties());
        context = contextAt(EVALUATION_TIME);
    }

    @Test
    void returnsColdStartUntilTheMinimumSampleExists() {
        history(List.of(
                "2026-09-14T08:00:00Z",
                "2026-09-07T08:00:00Z",
                "2026-08-31T08:00:00Z"
        ));

        TemporalRiskAssessment result = calculator.calculate(context);

        assertThat(result.status()).isEqualTo(TemporalProfileStatus.COLD_START);
        assertThat(result.riskScore()).isNull();
    }

    @Test
    void returnsZeroForAUsualDayAndHour() {
        history(List.of(
                "2026-09-14T08:00:00Z",
                "2026-09-07T07:00:00Z",
                "2026-08-31T09:00:00Z",
                "2026-08-24T08:00:00Z"
        ));

        TemporalRiskAssessment result = calculator.calculate(context);

        assertThat(result.status()).isEqualTo(TemporalProfileStatus.AVAILABLE);
        assertThat(result.riskScore()).isEqualByComparingTo(BigDecimal.ZERO);
    }

    @Test
    void returnsMediumRiskWhenOnlyTheDayIsUnusual() {
        history(List.of(
                "2026-09-15T08:00:00Z",
                "2026-09-09T07:00:00Z",
                "2026-09-03T09:00:00Z",
                "2026-08-28T08:00:00Z"
        ));

        TemporalRiskAssessment result = calculator.calculate(context);

        assertThat(result.riskScore()).isEqualByComparingTo("50");
    }

    @Test
    void returnsMediumRiskWhenOnlyTheHourIsUnusual() {
        history(List.of(
                "2026-09-14T14:00:00Z",
                "2026-09-07T15:00:00Z",
                "2026-08-31T14:00:00Z",
                "2026-08-24T15:00:00Z"
        ));

        TemporalRiskAssessment result = calculator.calculate(context);

        assertThat(result.riskScore()).isEqualByComparingTo("50");
    }

    @Test
    void returnsHighRiskWhenBothDayAndHourAreUnusual() {
        history(List.of(
                "2026-09-15T14:00:00Z",
                "2026-09-09T15:00:00Z",
                "2026-09-03T14:00:00Z",
                "2026-08-28T15:00:00Z"
        ));

        TemporalRiskAssessment result = calculator.calculate(context);

        assertThat(result.riskScore()).isEqualByComparingTo("100");
    }

    @Test
    void treatsTwentyThreeHundredAsAdjacentToMidnight() {
        LoginContext midnightContext = contextAt(Instant.parse("2026-09-21T00:00:00Z"));
        historyFor(midnightContext, List.of(
                "2026-09-14T23:00:00Z",
                "2026-09-07T23:00:00Z",
                "2026-08-31T23:00:00Z",
                "2026-08-24T23:00:00Z"
        ));

        TemporalRiskAssessment result = calculator.calculate(midnightContext);

        assertThat(result.riskScore()).isEqualByComparingTo(BigDecimal.ZERO);
    }

    @Test
    void buildsTheBaselineInTheConfiguredTimeZone() {
        TemporalRiskProperties localProperties = properties();
        localProperties.setZoneId(ZoneId.of("Asia/Ho_Chi_Minh"));
        calculator = new TemporalRiskCalculator(eventRepository, localProperties);
        LoginContext localContext = contextAt(Instant.parse("2026-09-21T00:30:00Z"));
        historyFor(localContext, List.of(
                "2026-09-13T23:30:00Z",
                "2026-09-06T23:30:00Z",
                "2026-08-30T23:30:00Z",
                "2026-08-23T23:30:00Z"
        ));

        TemporalRiskAssessment result = calculator.calculate(localContext);

        assertThat(result.riskScore()).isEqualByComparingTo(BigDecimal.ZERO);
    }

    @Test
    void returnsUnavailableWhenHistoryCannotBeRead() {
        when(eventRepository.findRecentAuthenticationTimes(
                eq(context.subjectId()),
                eq(context.clientId()),
                any(Instant.class),
                eq(EVALUATION_TIME),
                any(Pageable.class)
        )).thenThrow(new DataRetrievalFailureException("database unavailable"));

        TemporalRiskAssessment result = calculator.calculate(context);

        assertThat(result.status()).isEqualTo(TemporalProfileStatus.UNAVAILABLE);
        assertThat(result.riskScore()).isNull();
    }

    @Test
    void readsOnlyTheConfiguredWindowAndMaximumSample() {
        history(List.of(
                "2026-09-14T08:00:00Z",
                "2026-09-07T08:00:00Z",
                "2026-08-31T08:00:00Z",
                "2026-08-24T08:00:00Z"
        ));

        calculator.calculate(context);

        verify(eventRepository).findRecentAuthenticationTimes(
                eq("subject-1"),
                eq("zerotrust-spa"),
                eq(EVALUATION_TIME.minus(Duration.ofDays(30))),
                eq(EVALUATION_TIME),
                org.mockito.ArgumentMatchers.argThat(pageable ->
                        pageable.getPageNumber() == 0 && pageable.getPageSize() == 100)
        );
    }

    private void history(List<String> eventTimes) {
        historyFor(context, eventTimes);
    }

    private void historyFor(LoginContext requestedContext, List<String> eventTimes) {
        when(eventRepository.findRecentAuthenticationTimes(
                eq(requestedContext.subjectId()),
                eq(requestedContext.clientId()),
                any(Instant.class),
                eq(requestedContext.receivedAt()),
                any(Pageable.class)
        )).thenReturn(eventTimes.stream().map(Instant::parse).toList());
    }

    private LoginContext contextAt(Instant receivedAt) {
        return new LoginContext(
                "subject-1",
                "authentication-session-id",
                "zerotrust-spa",
                "203.0.113.10",
                "Mozilla/5.0",
                "device-1",
                receivedAt
        );
    }

    private TemporalRiskProperties properties() {
        TemporalRiskProperties properties = new TemporalRiskProperties();
        properties.setHistoryWindow(Duration.ofDays(30));
        properties.setMinimumEvents(4);
        properties.setMaximumEvents(100);
        properties.setZoneId(ZoneOffset.UTC);
        properties.setHourTolerance(1);
        properties.setMinimumDayFrequency(new BigDecimal("0.25"));
        properties.setMinimumHourFrequency(new BigDecimal("0.25"));
        properties.setMediumScore(new BigDecimal("50"));
        properties.setHighScore(new BigDecimal("100"));
        return properties;
    }
}
