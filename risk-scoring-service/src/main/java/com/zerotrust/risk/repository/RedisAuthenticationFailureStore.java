package com.zerotrust.risk.repository;

import com.zerotrust.risk.config.AuthenticationHistoryProperties;
import com.zerotrust.risk.service.AuthenticationHistoryKeyHasher;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;

@Repository
public class RedisAuthenticationFailureStore implements AuthenticationFailureStore {

    private static final DefaultRedisScript<Long> RECORD_FAILURE_SCRIPT =
            new DefaultRedisScript<>("""
                    -- Validate every predictable command error before any write. Lua errors do not roll back.
                    local function within(value, limit)
                        return #value < #limit or (#value == #limit and value <= limit)
                    end
                    local function incrementable(value)
                        if value == '0' then return true end
                        -- Failure counters are nonnegative; MAX cannot be incremented safely.
                        return value:match('^[1-9][0-9]*$') and within(value, '9223372036854775806')
                    end
                    -- EX/EXPIRE use a signed64 absolute millisecond deadline, not just signed64 seconds.
                    -- Subtract decimal strings; only individual digits and microseconds use Lua numbers.
                    local now = redis.call('TIME')
                    local millis = now[1] .. string.format('%03d', math.floor(tonumber(now[2]) / 1000))
                    local maximum = '9223372036854775807'
                    if not within(millis, maximum) then
                        return redis.error_reply('ERR invalid authentication failure clock')
                    end
                    local remaining, borrow = {}, 0
                    for index = #maximum, 1, -1 do
                        local offset = #millis - (#maximum - index)
                        local right = offset > 0 and millis:byte(offset) - 48 or 0
                        local digit = maximum:byte(index) - 48 - right - borrow
                        borrow = 0
                        if digit < 0 then digit, borrow = digit + 10, 1 end
                        remaining[index] = string.char(48 + digit)
                    end
                    local ttlLimit = table.concat(remaining):sub(1, -4):gsub('^0+', '')
                    for index = 1, 2 do
                        local ttl = ARGV[index]
                        if not ttl or not ttl:match('^[1-9][0-9]*$') or not within(ttl, ttlLimit) then
                            return redis.error_reply('ERR invalid authentication failure expiry')
                        end
                    end
                    -- Existing event IDs keep their original payload-independent duplicate semantics.
                    if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
                    for index = 2, #KEYS do
                        local kind = redis.call('TYPE', KEYS[index]).ok
                        if kind ~= 'none' then
                            if kind ~= 'string' or not incrementable(redis.call('GET', KEYS[index])) then
                                return redis.error_reply('ERR authentication failure counter cannot be incremented')
                            end
                        end
                    end
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
                throw new DataRetrievalFailureException("Authentication failure count must not be negative");
            }
            return count;
        } catch (NumberFormatException exception) {
            throw new DataRetrievalFailureException("Authentication failure count is invalid", exception);
        }
    }

    private String key(String category, String scope, String value) {
        return keyPrefix + ':' + category + ':' + keyHasher.hash(scope, value);
    }
}
