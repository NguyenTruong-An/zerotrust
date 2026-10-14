package com.zerotrust.risk.audit.redis;

import com.zerotrust.risk.domain.RiskDataStatus;
import com.zerotrust.risk.domain.RiskDecision;
import com.zerotrust.risk.domain.RiskReason;
import com.zerotrust.risk.service.AuthenticationFailureService;
import org.assertj.core.api.SoftAssertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.RedisCallback;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.*;

/** Native state oracle: literal business-invalid values and Redis absolute expiry, not Lua validation. */
@EnabledIfSystemProperty(named = "qa.redis.audit", matches = "true")
class RedisNegativeCounterRegressionTests extends RedisAuditSupport {
    private static final String SUBJECT = "subject1", IP = "203.0.113.10";

    @ParameterizedTest @ValueSource(strings = {"subject", "ip"})
    void originalNegativeStateEvidenceIncludesAbsentHealthyCounter(String scope) {
        rejectRepairAndRetry(scope, "-1", null);
    }

    @ParameterizedTest @CsvSource({
            "subject,-1", "ip,-1", "subject,-2", "ip,-2",
            "subject,-9223372036854775808", "ip,-9223372036854775808",
            "subject,-9007199254740993", "ip,-9007199254740993",
            "subject,-9223372036854775806", "ip,-9223372036854775806"})
    void negativeCounterCannotConsumeAnyEventOrChangeHealthyState(String scope, String negative) {
        rejectRepairAndRetry(scope, negative, "5");
    }

    private void rejectRepairAndRetry(String scope, String negative, String healthyValue) {
        track("negative", SUBJECT, IP); track("new-id", SUBJECT, IP);
        String bad = scope.equals("subject") ? subject(SUBJECT) : ip(IP);
        String healthy = scope.equals("subject") ? ip(IP) : subject(SUBJECT);
        seed(bad, negative);
        if (healthyValue != null) {
            seed(healthy, healthyValue); primary.template.expire(healthy, Duration.ofSeconds(30));
        }
        State subjectBefore = state(subject(SUBJECT)), ipBefore = state(ip(IP)), markerBefore = state(event("negative"));
        var before = RedisRiskHarness.evaluate(store());
        AtomicReference<Boolean> accepted = new AtomicReference<>();
        Throwable error = catchThrowable(() -> accepted.set(new AuthenticationFailureService(store()).recordFailure("negative", SUBJECT, IP)));
        State subjectAfter = state(subject(SUBJECT)), ipAfter = state(ip(IP)), markerAfter = state(event("negative"));
        var after = RedisRiskHarness.evaluate(store());
        evidence("ORIGINAL subjectKey=" + subject(SUBJECT) + " ipKey=" + ip(IP) + " eventKey=" + event("negative")
                + " BEFORE subject=" + subjectBefore + " ip=" + ipBefore + " marker=" + markerBefore + " risk=" + before
                + " AFTER subject=" + subjectAfter + " ip=" + ipAfter + " marker=" + markerAfter + " luaResult=" + accepted.get()
                + " exception=" + (error == null ? "none" : rootCause(error)) + " historyAvailable="
                + !after.reasons().contains(RiskReason.AUTHENTICATION_HISTORY_UNAVAILABLE) + " risk=" + after);
        SoftAssertions s = new SoftAssertions();
        incomplete(s, before); incomplete(s, after); s.assertThat(error).isInstanceOf(DataAccessException.class);
        same(s, subjectBefore, subjectAfter); same(s, ipBefore, ipAfter); same(s, markerBefore, markerAfter);
        for (String id : new String[]{"negative", "new-id"}) {
            s.assertThat(catchThrowable(() -> store().recordFailure(id, SUBJECT, IP))).isInstanceOf(DataAccessException.class);
            s.assertThat(state(event(id)).type()).isEqualTo("none");
        }
        // Explicit fixture recovery of this case's bad key; production must never perform this SET.
        seed(bad, "0");
        boolean retry = store().recordFailure("negative", SUBJECT, IP), duplicate = store().recordFailure("negative", SUBJECT, IP);
        s.assertThat(retry).isTrue(); s.assertThat(duplicate).isFalse(); s.assertThat(get(bad)).isEqualTo("1");
        s.assertThat(get(healthy)).isEqualTo(healthyValue == null ? "1" : "6");
        var repaired = RedisRiskHarness.evaluate(store());
        s.assertThat(repaired.dataStatus()).isEqualTo(RiskDataStatus.COMPLETE);
        s.assertThat(repaired.reasons()).doesNotContain(RiskReason.AUTHENTICATION_HISTORY_UNAVAILABLE);
        evidence("EXPLICIT REPAIR retry=" + retry + " duplicate=" + duplicate + " bad=" + state(bad) + " healthy=" + state(healthy) + " risk=" + repaired);
        s.assertAll();
    }

    @ParameterizedTest @ValueSource(strings = {"-1", "-2", "-9223372036854775808"})
    void twoNegativeCountersStayUnchangedUntilBothAreExplicitlyRepaired(String value) {
        track("both", SUBJECT, IP); seed(subject(SUBJECT), value); seed(ip(IP), value);
        State a = state(subject(SUBJECT)), b = state(ip(IP));
        Throwable error = catchThrowable(() -> store().recordFailure("both", SUBJECT, IP));
        State afterA = state(subject(SUBJECT)), afterB = state(ip(IP));
        evidence("BOTH before=" + a + '/' + b + " after=" + afterA + '/' + afterB + " error=" + (error == null ? "none" : rootCause(error)));
        SoftAssertions s = new SoftAssertions(); s.assertThat(error).isInstanceOf(DataAccessException.class);
        same(s, a, afterA); same(s, b, afterB); s.assertThat(get(event("both"))).isNull();
        seed(subject(SUBJECT), "0"); seed(ip(IP), "0");
        s.assertThat(store().recordFailure("both", SUBJECT, IP)).isTrue();
        s.assertThat(store().recordFailure("both", SUBJECT, IP)).isFalse();
        s.assertThat(get(subject(SUBJECT))).isEqualTo("1"); s.assertThat(get(ip(IP))).isEqualTo("1"); s.assertAll();
    }

    @ParameterizedTest @ValueSource(strings = {"-1", "-2", "-9223372036854775808"})
    void ipOnlyEventRejectsNegativeIpWithoutCreatingASubject(String value) {
        track("ip-only", null, IP); seed(ip(IP), value); State before = state(ip(IP));
        assertThatThrownBy(() -> new AuthenticationFailureService(store()).recordFailure("ip-only", null, IP)).isInstanceOf(DataAccessException.class);
        same(before, state(ip(IP))); assertThat(get(event("ip-only"))).isNull(); assertThat(get(subject(SUBJECT))).isNull();
        seed(ip(IP), "0"); assertThat(store().recordFailure("ip-only", null, IP)).isTrue();
        assertThat(store().recordFailure("ip-only", null, IP)).isFalse(); assertThat(get(ip(IP))).isEqualTo("1");
    }

    @ParameterizedTest @CsvSource({"subject,true", "subject,false", "ip,true", "ip,false"})
    void concurrentRejectionAndControlledRepairRetainEventIdempotency(String scope, boolean sameEvent) throws Exception {
        for (int i = 0; i < 8; i++) track(sameEvent ? "same" : "event" + i, SUBJECT, IP);
        String bad = scope.equals("subject") ? subject(SUBJECT) : ip(IP), healthy = scope.equals("subject") ? ip(IP) : subject(SUBJECT);
        seed(bad, "-1"); seed(healthy, "5"); State a = state(bad), b = state(healthy);
        assertThat(concurrent(8, (i, c) -> {
            assertThatThrownBy(() -> store(c).recordFailure(sameEvent ? "same" : "event" + i, SUBJECT, IP)).isInstanceOf(DataAccessException.class); return false;
        })).isZero();
        same(a, state(bad)); same(b, state(healthy));
        for (int i = 0; i < 8; i++) assertThat(get(event(sameEvent ? "same" : "event" + i))).isNull();
        // All futures finished before repair; the subsequent wave uses independently synchronized clients.
        seed(bad, "0");
        assertThat(concurrent(8, (i, c) -> store(c).recordFailure(sameEvent ? "same" : "event" + i, SUBJECT, IP))).isEqualTo(sameEvent ? 1 : 8);
        assertThat(get(bad)).isEqualTo(sameEvent ? "1" : "8"); assertThat(get(healthy)).isEqualTo(sameEvent ? "6" : "13");
    }

    @ParameterizedTest @ValueSource(strings = {"subject", "ip"})
    void alreadyProcessedDuplicateDoesNotRepairOrHideLaterCorruption(String scope) {
        track("done", SUBJECT, IP); assertThat(store().recordFailure("done", SUBJECT, IP)).isTrue();
        String bad = scope.equals("subject") ? subject(SUBJECT) : ip(IP); seed(bad, "-1");
        State a = state(subject(SUBJECT)), b = state(ip(IP)), marker = state(event("done"));
        assertThat(store().recordFailure("done", SUBJECT, IP)).isFalse();
        same(a, state(subject(SUBJECT))); same(b, state(ip(IP))); same(marker, state(event("done")));
        SoftAssertions s = new SoftAssertions(); incomplete(s, RedisRiskHarness.evaluate(store())); s.assertAll();
    }

    @Test void securityRevocationDenyPrecedesIncompleteNegativeHistory() {
        seed(subject(SUBJECT), "-1");
        var result = RedisRiskHarness.evaluate(store(), true);
        assertThat(result.decision()).isEqualTo(RiskDecision.DENY);
        assertThat(result.dataStatus()).isEqualTo(RiskDataStatus.NOT_EVALUATED);
        assertThat(result.reasons()).contains(RiskReason.REVOKED_DEVICE);
    }

    @Test void distinctUsersAndIpsRemainIsolatedWhileOneCounterIsCorrupt() {
        track("bad", SUBJECT, IP); track("good", "subject2", "203.0.113.11"); seed(subject(SUBJECT), "-1"); State bad = state(subject(SUBJECT));
        assertThatThrownBy(() -> store().recordFailure("bad", SUBJECT, IP)).isInstanceOf(DataAccessException.class);
        assertThat(store().recordFailure("good", "subject2", "203.0.113.11")).isTrue();
        assertThat(store().recordFailure("good", "subject2", "203.0.113.11")).isFalse();
        same(bad, state(subject(SUBJECT))); assertThat(get(event("bad"))).isNull(); assertThat(get(ip(IP))).isNull();
        counters("subject2", "203.0.113.11", 1, 1);
    }

    @Test void positiveOneRetainsExpiryAndIncrementsExactlyOnce() {
        track("positive", SUBJECT, IP); seed(subject(SUBJECT), "1"); seed(ip(IP), "1");
        long a = state(subject(SUBJECT)).expiry(), b = state(ip(IP)).expiry();
        assertThat(store().recordFailure("positive", SUBJECT, IP)).isTrue(); assertThat(store().recordFailure("positive", SUBJECT, IP)).isFalse();
        counters(SUBJECT, IP, 2, 2); assertThat(state(subject(SUBJECT)).expiry()).isEqualTo(a); assertThat(state(ip(IP)).expiry()).isEqualTo(b);
    }

    record State(String type, String value, long expiry, long pttl) {}
    private State state(String key) {
        String type = primary.template.type(key).code(), value = type.equals("string") ? get(key) : "<" + type + ">";
        long expiry = Objects.requireNonNull(primary.template.execute((RedisCallback<Long>) c -> {
            @SuppressWarnings("unchecked") var commands = (io.lettuce.core.api.async.RedisAsyncCommands<byte[], byte[]>) c.getNativeConnection();
            return commands.pexpiretime(key.getBytes(StandardCharsets.UTF_8)).toCompletableFuture().join();
        }));
        return new State(type, value, expiry, ttl(key));
    }
    private void same(State a, State b) { SoftAssertions s = new SoftAssertions(); same(s, a, b); s.assertAll(); }
    private void same(SoftAssertions s, State a, State b) {
        s.assertThat(b.type()).isEqualTo(a.type()); s.assertThat(b.value()).isEqualTo(a.value()); s.assertThat(b.expiry()).isEqualTo(a.expiry());
    }
    private void incomplete(SoftAssertions s, com.zerotrust.risk.domain.RiskEvaluation result) {
        s.assertThat(result.dataStatus()).isEqualTo(RiskDataStatus.INCOMPLETE); s.assertThat(result.riskScore()).isNull();
        s.assertThat(result.decision()).isEqualTo(RiskDecision.STEP_UP_MFA); s.assertThat(result.reasons()).contains(RiskReason.AUTHENTICATION_HISTORY_UNAVAILABLE);
    }
    interface Request { boolean apply(int index, Client client); }
    private long concurrent(int n, Request request) throws Exception {
        var connections = new ArrayList<Client>(); for (int i = 0; i < n; i++) connections.add(client());
        var ids = connections.stream().map(Client::id).toList(); assertThat(new HashSet<>(ids)).hasSize(n);
        var barrier = new CyclicBarrier(n + 1); var pool = Executors.newFixedThreadPool(n);
        try {
            var futures = new ArrayList<Future<Boolean>>();
            for (int i = 0; i < n; i++) { int index = i; futures.add(pool.submit(() -> { barrier.await(5, TimeUnit.SECONDS); return request.apply(index, connections.get(index)); })); }
            barrier.await(5, TimeUnit.SECONDS); long accepted = 0;
            for (var future : futures) if (future.get(8, TimeUnit.SECONDS)) accepted++;
            evidence("CONCURRENT clients=" + ids + " accepted=" + accepted); return accepted;
        } finally { pool.shutdownNow(); assertThat(pool.awaitTermination(5, TimeUnit.SECONDS)).isTrue(); }
    }
}
