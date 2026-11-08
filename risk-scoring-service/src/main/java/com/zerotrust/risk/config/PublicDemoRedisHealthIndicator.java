package com.zerotrust.risk.config;

import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.context.annotation.Profile;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

import java.util.List;

@Component("redis")
@Profile("public-demo")
final class PublicDemoRedisHealthIndicator implements HealthIndicator {
    private static final DefaultRedisScript<Long> CHECK_HISTORY_ACCESS = new DefaultRedisScript<>("""
            #!lua
            local can = redis.acl_check_cmd
            if not can('EVAL', 'return 1', 3, KEYS[1], KEYS[2], KEYS[3])
                or not can('EXISTS', KEYS[1])
                or not can('SET', KEYS[1], '1', 'EX', 1, 'NX') then
                return 0
            end
            for i = 2, 3 do
                local key = KEYS[i]
                if not can('TYPE', key) or not can('GET', key)
                    or not can('INCR', key) or not can('EXPIRE', key, 1) then
                    return 0
                end
            end
            redis.call('TIME')
            return 1
            """, Long.class);

    private final StringRedisTemplate redis;
    private final List<String> historyKeys;

    PublicDemoRedisHealthIndicator(StringRedisTemplate redis, AuthenticationHistoryProperties properties) {
        this.redis = redis;
        String prefix = properties.getKeyPrefix();
        String probeSuffix = ":" + "0".repeat(64);
        this.historyKeys = List.of(prefix + ":event" + probeSuffix,
                prefix + ":failure:subject" + probeSuffix, prefix + ":failure:ip" + probeSuffix);
    }

    @Override
    public Health health() {
        try {
            // Same connection and scripting path as the failure store. Check writes without creating keys.
            Long result = redis.execute(CHECK_HISTORY_ACCESS, historyKeys);
            return Long.valueOf(1).equals(result) ? Health.up().build() : Health.down().build();
        } catch (DataAccessException exception) {
            return Health.down().build();
        }
    }
}
