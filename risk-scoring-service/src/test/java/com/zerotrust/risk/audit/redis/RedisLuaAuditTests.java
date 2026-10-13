package com.zerotrust.risk.audit.redis;

import com.zerotrust.risk.service.AuthenticationFailureService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.dao.DataAccessException;
import org.assertj.core.api.SoftAssertions;
import java.time.Duration;

import static org.assertj.core.api.Assertions.*;

@EnabledIfSystemProperty(named = "qa.redis.audit", matches = "true")
class RedisLuaAuditTests extends RedisAuditSupport {
    @Test void realScriptRecordsBothCountersAndRejectsRetry() {
        track("event1", "subject1", "203.0.113.10");
        var store = store();
        assertThat(store.recordFailure("event1", "subject1", "203.0.113.10")).isTrue();
        assertThat(store.recordFailure("event1", "subject1", "203.0.113.10")).isFalse();
        counters("subject1", "203.0.113.10", 1, 1);
        assertThat(get(event("event1"))).isEqualTo("1");
        evidence("actual Lua returns true then false; counters=1/1 dedup=1");
    }
    @Test void unknownSubjectOnlyCountsIp() {
        track("unknown1", null, "203.0.113.11");
        assertThat(store().recordFailure("unknown1", null, "203.0.113.11")).isTrue();
        assertThat(store().countBySourceIp("203.0.113.11")).isEqualTo(1);
        assertThat(get(subject("absent"))).isNull();
    }
    @Test void canonicalSubjectEventAndIpShareKeysWithoutScopeCollision() {
        track("canonical", "subject1", "203.0.113.10");
        var service = new AuthenticationFailureService(store());
        assertThat(service.recordFailure(" canonical ", " subject1 ", " 203.000.113.010 ")).isTrue();
        assertThat(service.recordFailure("canonical", "subject1", "203.0.113.10")).isFalse();
        counters(" subject1 ", "203.0.113.10", 1, 1);
        assertThat(subject("subject1")).isNotEqualTo(event("subject1"));
        assertThat(get(subject("subject2"))).isNull();
    }
    @Test void equivalentIpv6RepresentationsReadTheSameRealCounter() {
        track("v6event", "subject1", "2001:db8:0:0:0:0:0:1");
        assertThat(store().recordFailure("v6event", "subject1", "2001:0DB8::1")).isTrue();
        assertThat(store().countBySourceIp("2001:db8:0:0:0:0:0:1")).isEqualTo(1);
        assertThat(get(ip("2001:db8:0:0:0:0:0:1"))).isEqualTo("1");
    }
    @Test void invalidIpIsRejectedBeforeAnyRedisMutation() {
        event("badip"); subject("subject1");
        assertThatThrownBy(() -> store().recordFailure("badip", "subject1", "example.invalid"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(get(event("badip"))).isNull(); assertThat(get(subject("subject1"))).isNull();
    }

    @ParameterizedTest(name = "script error must leave no partial mutation: {0}/{1}")
    @CsvSource({"subject,invalid", "ip,invalid", "ip,9223372036854775807", "ip,list"})
    void scriptErrorMustNotConsumeEventOrLeavePartialCounters(String corruptScope, String corruption) {
        track("failed-event", "subject1", "203.0.113.10");
        String badKey = corruptScope.equals("subject") ? subject("subject1") : ip("203.0.113.10");
        if (corruption.equals("list")) {
            primary.template.opsForList().rightPush(badKey, "bad-type"); primary.template.expire(badKey, Duration.ofSeconds(60));
        } else seed(badKey, corruption);
        Throwable error = catchThrowable(() -> store().recordFailure("failed-event", "subject1", "203.0.113.10"));
        assertThat(error).isInstanceOf(DataAccessException.class);
        String dedup = get(event("failed-event"));
        String healthy = get(corruptScope.equals("subject") ? ip("203.0.113.10") : subject("subject1"));
        // Fixture repair only the intentionally corrupt QA key, then retry original event.
        seed(badKey, "0");
        boolean retry = store().recordFailure("failed-event", "subject1", "203.0.113.10");
        evidence("ERROR=" + error.getClass().getSimpleName() + " root=" + rootCause(error) + " dedupAfterError=" + dedup + " healthyAfterError=" + healthy + " retry=" + retry + " final=" + get(subject("subject1")) + '/' + get(ip("203.0.113.10")));
        SoftAssertions softly = new SoftAssertions();
        softly.assertThat(dedup).as("Failed Lua must not permanently mark event processed").isNull();
        softly.assertThat(healthy).as("Healthy counter must not be mutated by failed event").isNull();
        softly.assertThat(retry).as("Retry after corrupt key repair must process the event").isTrue();
        softly.assertThat(store().countBySubject("subject1")).isEqualTo(1);
        softly.assertThat(store().countBySourceIp("203.0.113.10")).isEqualTo(1);
        softly.assertAll();
    }
}
