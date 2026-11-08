package com.zerotrust.risk.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Status;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PublicDemoRedisHealthIndicatorTests {
    private static final String PREFIX = "synthetic:history";
    private static final String SUFFIX = ":" + "0".repeat(64);
    private static final List<String> HISTORY_KEYS = List.of(PREFIX + ":event" + SUFFIX,
            PREFIX + ":failure:subject" + SUFFIX, PREFIX + ":failure:ip" + SUFFIX);

    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);

    @Test
    void onlyAnAffirmativeHistoryAccessResultIsHealthy() {
        when(redis.<Long>execute(any(), eq(HISTORY_KEYS)))
                .thenReturn(1L, 0L, null);
        var indicator = indicator();

        assertThat(indicator.health().getStatus()).isEqualTo(Status.UP);
        assertThat(indicator.health().getStatus()).isEqualTo(Status.DOWN);
        assertThat(indicator.health().getStatus()).isEqualTo(Status.DOWN);
    }

    @Test
    void connectionErrorsMarkReadinessDownWithoutExposingDetails() {
        when(redis.<Long>execute(any(), eq(HISTORY_KEYS)))
                .thenThrow(new RedisConnectionFailureException("internal connection detail"));

        var result = indicator().health();
        assertThat(result.getStatus()).isEqualTo(Status.DOWN);
        assertThat(result.getDetails()).isEmpty();
    }

    private PublicDemoRedisHealthIndicator indicator() {
        var properties = new AuthenticationHistoryProperties();
        properties.setKeyPrefix(PREFIX);
        return new PublicDemoRedisHealthIndicator(redis, properties);
    }
}
