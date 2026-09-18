package com.zerotrust.risk.repository;

import com.zerotrust.risk.config.AuthenticationHistoryProperties;
import com.zerotrust.risk.service.AuthenticationHistoryKeyHasher;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;

@Repository
public class RedisAuthenticationFailureStore implements AuthenticationFailureStore {

    private static final DefaultRedisScript<Long> RECORD_FAILURE_SCRIPT =
            new DefaultRedisScript<>("""
                    local inserted = redis.call('SET', KEYS[1], '1', 'EX', ARGV[1], 'NX')
                    if not inserted then
                        return 0
                    end
                    for index = 2, #KEYS do
                        local count = redis.call('INCR', KEYS[index])
                        if count == 1 then
                            redis.call('EXPIRE', KEYS[index], ARGV[2])
                        end
                    end
                    return 1
                    """, Long.class);

    private final StringRedisTemplate redisTemplate;
    private final AuthenticationHistoryKeyHasher keyHasher;
    private final String keyPrefix;
    private final long failureWindowSeconds;
    private final long eventDeduplicationSeconds;

    public RedisAuthenticationFailureStore(
            StringRedisTemplate redisTemplate,
            AuthenticationHistoryKeyHasher keyHasher,
            AuthenticationHistoryProperties properties
    ) {
        this.redisTemplate = redisTemplate;
        this.keyHasher = keyHasher;
        this.keyPrefix = properties.getKeyPrefix();
        this.failureWindowSeconds = properties.getFailureWindow().toSeconds();
        this.eventDeduplicationSeconds = properties.getEventDeduplicationTtl().toSeconds();
    }

    @Override
    public boolean recordFailure(String eventId, String subjectId, String sourceIp) {
        List<String> keys = new ArrayList<>();
        keys.add(key("event", "event", eventId));
        if (subjectId != null) {
            keys.add(key("failure:subject", "subject", subjectId));
        }
        keys.add(key("failure:ip", "ip", sourceIp));

        Long result = redisTemplate.execute(
                RECORD_FAILURE_SCRIPT,
                keys,
                Long.toString(eventDeduplicationSeconds),
                Long.toString(failureWindowSeconds)
        );
        if (result == null) {
            throw new IllegalStateException("Redis did not return an authentication failure result");
        }
        return result == 1L;
    }

    @Override
    public long countBySubject(String subjectId) {
        return readCount(key("failure:subject", "subject", subjectId));
    }

    @Override
    public long countBySourceIp(String sourceIp) {
        return readCount(key("failure:ip", "ip", sourceIp));
    }

    private long readCount(String key) {
        String value = redisTemplate.opsForValue().get(key);
        if (value == null) {
            return 0L;
        }
        try {
            long count = Long.parseLong(value);
            if (count < 0) {
                throw new IllegalStateException("Authentication failure count must not be negative");
            }
            return count;
        } catch (NumberFormatException exception) {
            throw new IllegalStateException("Authentication failure count is invalid", exception);
        }
    }

    private String key(String category, String scope, String value) {
        return keyPrefix + ':' + category + ':' + keyHasher.hash(scope, value);
    }
}
