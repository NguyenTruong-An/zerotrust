package com.zerotrust.risk.repository;

import com.zerotrust.risk.config.AuthenticationHistoryProperties;
import com.zerotrust.risk.config.AuthenticationHistoryRiskProperties;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.service.AuthenticationHistoryKeyHasher;
import com.zerotrust.risk.service.AuthenticationHistoryRiskCalculator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.script.RedisScript;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RedisAuthenticationFailureStoreTests {

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    private RedisAuthenticationFailureStore store;

    @BeforeEach
    void setUp() {
        AuthenticationHistoryProperties properties = new AuthenticationHistoryProperties();
        properties.setPepper("test-only-authentication-history-pepper-value");
        properties.setKeyPrefix("zerotrust:risk:auth-history");
        properties.setFailureWindow(Duration.ofMinutes(15));
        properties.setEventDeduplicationTtl(Duration.ofHours(1));
        AuthenticationHistoryKeyHasher hasher = new AuthenticationHistoryKeyHasher(properties);
        store = new RedisAuthenticationFailureStore(redisTemplate, hasher, properties);
    }

    @Test
    @SuppressWarnings("unchecked")
    void recordsSubjectAndIpAtomicallyWithoutRawIdentifiersInKeys() {
        when(redisTemplate.execute(
                any(RedisScript.class), anyList(), any(), any()
        )).thenReturn(1L);

        boolean recorded = store.recordFailure(
                "event-1",
                "subject-1",
                "203.0.113.10"
        );

        ArgumentCaptor<List<String>> keys = ArgumentCaptor.forClass(List.class);
        verify(redisTemplate).execute(
                any(RedisScript.class),
                keys.capture(),
                eq("3600"),
                eq("900")
        );
        assertThat(recorded).isTrue();
        assertThat(keys.getValue()).hasSize(3);
        assertThat(keys.getValue()).allSatisfy(key -> {
            assertThat(key).startsWith("zerotrust:risk:auth-history:");
            assertThat(key)
                    .doesNotContain("event-1")
                    .doesNotContain("subject-1")
                    .doesNotContain("203.0.113.10");
        });
    }

    @Test
    @SuppressWarnings("unchecked")
    void unknownSubjectOnlyIncrementsIpAndDuplicateEventIsIgnored() {
        when(redisTemplate.execute(
                any(RedisScript.class), anyList(), any(), any()
        )).thenReturn(0L);

        boolean recorded = store.recordFailure("event-1", null, "203.0.113.10");

        ArgumentCaptor<List<String>> keys = ArgumentCaptor.forClass(List.class);
        verify(redisTemplate).execute(
                any(RedisScript.class), keys.capture(), eq("3600"), eq("900")
        );
        assertThat(recorded).isFalse();
        assertThat(keys.getValue()).hasSize(2);
    }

    @Test
    void returnsZeroForMissingCounterAndParsesExistingCounter() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(any(String.class))).thenReturn(null, "3");

        assertThat(store.countBySubject("subject-1")).isZero();
        assertThat(store.countBySourceIp("203.0.113.10")).isEqualTo(3L);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(longs = {-1, 2})
    @SuppressWarnings("unchecked")
    void rejectsMissingOrUnexpectedScriptResult(Long result) {
        when(redisTemplate.execute(any(RedisScript.class), anyList(), any(), any())).thenReturn(result);

        assertThatThrownBy(() -> store.recordFailure("event-1", "subject-1", "203.0.113.10"))
                .isInstanceOf(DataRetrievalFailureException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"-1", "invalid", "9223372036854775808"})
    void corruptedCounterMakesHistoryUnavailable(String value) {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(any(String.class))).thenReturn(value);
        AuthenticationHistoryRiskCalculator calculator = new AuthenticationHistoryRiskCalculator(
                store, new AuthenticationHistoryRiskProperties());
        LoginContext context = new LoginContext("subject-1", "session-1", "client-1",
                "203.0.113.10", "test-agent", "device-1", Instant.parse("2026-10-07T00:00:00Z"));

        assertThat(calculator.calculate(context)).isEmpty();
    }

    @Test
    void corruptedIpCounterMakesHistoryUnavailableEvenWithValidSubjectCounter() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(any(String.class))).thenReturn("0", "invalid");
        AuthenticationHistoryRiskCalculator calculator = new AuthenticationHistoryRiskCalculator(
                store, new AuthenticationHistoryRiskProperties());
        LoginContext context = new LoginContext("subject-1", "session-1", "client-1",
                "203.0.113.10", "test-agent", "device-1", Instant.parse("2026-10-07T00:00:00Z"));

        assertThat(calculator.calculate(context)).isEmpty();
    }

    @Test
    @SuppressWarnings("unchecked")
    void readsTheRecordedCounterUsingAnEquivalentIpv6Address() {
        when(redisTemplate.execute(any(RedisScript.class), anyList(), any(), any()))
                .thenReturn(1L);
        store.recordFailure("event-ipv6", null, "2001:0DB8::1");
        ArgumentCaptor<List<String>> keys = ArgumentCaptor.forClass(List.class);
        verify(redisTemplate).execute(
                any(RedisScript.class), keys.capture(), eq("3600"), eq("900")
        );
        String recordedIpKey = keys.getValue().get(1);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(recordedIpKey)).thenReturn("7");

        assertThat(store.countBySourceIp("2001:db8:0:0:0:0:0:1")).isEqualTo(7L);
        verify(valueOperations).get(recordedIpKey);
    }
}
