package com.zerotrust.risk.service;

import com.zerotrust.risk.config.AuthenticationHistoryRiskProperties;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.repository.AuthenticationFailureStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataAccessResourceFailureException;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationHistoryRiskCalculatorTests {

    @Mock
    private AuthenticationFailureStore failureStore;

    private AuthenticationHistoryRiskCalculator calculator;
    private LoginContext context;

    @BeforeEach
    void setUp() {
        calculator = new AuthenticationHistoryRiskCalculator(failureStore, properties());
        context = new LoginContext(
                "subject-1",
                "authentication-session-id",
                "zerotrust-spa",
                "203.0.113.10",
                "Mozilla/5.0",
                "device-1",
                Instant.parse("2026-09-16T08:00:00Z")
        );
    }

    @Test
    void returnsZeroWhenBothCountersAreBelowMediumThresholds() {
        counters(2, 9);

        Optional<BigDecimal> result = calculator.calculate(context);

        assertThat(result).contains(BigDecimal.ZERO);
    }

    @Test
    void usesSubjectCounterAtTheMediumBand() {
        counters(3, 0);

        Optional<BigDecimal> result = calculator.calculate(context);

        assertThat(result).contains(new BigDecimal("50"));
    }

    @Test
    void usesSourceIpCounterAtTheHighBand() {
        counters(0, 20);

        Optional<BigDecimal> result = calculator.calculate(context);

        assertThat(result).contains(new BigDecimal("100"));
    }

    @Test
    void takesMaximumInsteadOfAddingTheSameFailureTwice() {
        counters(3, 10);

        Optional<BigDecimal> result = calculator.calculate(context);

        assertThat(result).contains(new BigDecimal("50"));
    }

    @Test
    void returnsUnavailableWhenRedisCannotBeRead() {
        when(failureStore.countBySubject(context.subjectId()))
                .thenThrow(new DataAccessResourceFailureException("Redis unavailable"));

        Optional<BigDecimal> result = calculator.calculate(context);

        assertThat(result).isEmpty();
    }

    private void counters(long subjectFailures, long sourceIpFailures) {
        when(failureStore.countBySubject(context.subjectId())).thenReturn(subjectFailures);
        when(failureStore.countBySourceIp(context.ipAddress())).thenReturn(sourceIpFailures);
    }

    private AuthenticationHistoryRiskProperties properties() {
        AuthenticationHistoryRiskProperties properties =
                new AuthenticationHistoryRiskProperties();
        properties.setSubjectMediumMinimum(3);
        properties.setSubjectHighMinimum(5);
        properties.setSourceIpMediumMinimum(10);
        properties.setSourceIpHighMinimum(20);
        properties.setMediumScore(new BigDecimal("50"));
        properties.setHighScore(new BigDecimal("100"));
        return properties;
    }
}
