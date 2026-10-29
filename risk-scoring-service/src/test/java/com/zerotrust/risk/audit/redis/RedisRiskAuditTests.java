package com.zerotrust.risk.audit.redis;

import com.zerotrust.risk.domain.*;
import com.zerotrust.risk.service.AuthenticationHistoryRiskCalculator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.dao.DataAccessException;
import org.assertj.core.api.SoftAssertions;
import java.time.Duration;
import static org.assertj.core.api.Assertions.*;

@EnabledIfSystemProperty(named = "qa.redis.audit", matches = "true")
class RedisRiskAuditTests extends RedisAuditSupport {
    @ParameterizedTest(name = "real counters {0}={1} => score {2}, high={3}")
    @CsvSource({"subject,2,0,false", "subject,3,50,false", "subject,4,50,false", "subject,5,100,true", "subject,6,100,true",
            "ip,9,0,false", "ip,10,50,false", "ip,19,50,false", "ip,20,100,true", "ip,21,100,true"})
    void realFailureEventsFeedBoundaryClassificationAndMandatoryMfa(String scope, int count, String score, boolean high) {
        String subject = scope.equals("subject") ? "subject1" : null;
        for (int i = 0; i < count; i++) { track("event" + i, subject, "203.0.113.10"); assertThat(store().recordFailure("event" + i, subject, "203.0.113.10")).isTrue(); }
        var assessment = new AuthenticationHistoryRiskCalculator(store(), thresholds(), new com.zerotrust.risk.config.RiskPolicyProperties()).calculate(RedisRiskHarness.context()).orElseThrow();
        assertThat(assessment.riskScore()).isEqualByComparingTo(score); assertThat(assessment.highRisk()).isEqualTo(high);
        var result = RedisRiskHarness.evaluate(store());
        assertThat(result.dataStatus()).isEqualTo(RiskDataStatus.COMPLETE);
        assertThat(result.riskScore()).isEqualByComparingTo(assessment.riskScore().multiply(new java.math.BigDecimal("0.25")));
        assertThat(result.decision()).isEqualTo(high ? RiskDecision.STEP_UP_MFA : RiskDecision.ALLOW);
        if (high) assertThat(result.reasons()).contains(RiskReason.EXCESSIVE_AUTHENTICATION_FAILURES);
        evidence("COUNTERS subject=" + store().countBySubject("subject1") + " ip=" + store().countBySourceIp("203.0.113.10") + " historyScore=" + assessment.riskScore() + " high=" + high + " result=" + result);
    }
    @ParameterizedTest(name = "corrupt {0}={1} must remain incomplete/MFA")
    @CsvSource({"subject,-1", "subject,invalid", "subject,9223372036854775808", "ip,-1", "ip,invalid", "ip,9223372036854775808"})
    void corruptionOfEitherRealCounterCannotProduceAllow(String scope, String corruption) {
        seed(subject("subject1"), "0"); seed(ip("203.0.113.10"), "0");
        seed(scope.equals("subject") ? subject("subject1") : ip("203.0.113.10"), corruption);
        var result = RedisRiskHarness.evaluate(store());
        assertThat(result.dataStatus()).isEqualTo(RiskDataStatus.INCOMPLETE);
        assertThat(result.decision()).isEqualTo(RiskDecision.STEP_UP_MFA);
        assertThat(result.riskScore()).isNull(); assertThat(result.reasons()).contains(RiskReason.AUTHENTICATION_HISTORY_UNAVAILABLE);
        evidence("Malformed counter read => " + result);
    }
    @Test void wrongRedisTypeOnIpCannotProduceAllow() {
        seed(subject("subject1"), "0"); String key = ip("203.0.113.10");
        primary.template.opsForList().rightPush(key, "wrongtype"); primary.template.expire(key, Duration.ofSeconds(60));
        var result = RedisRiskHarness.evaluate(store());
        assertThat(result.dataStatus()).isEqualTo(RiskDataStatus.INCOMPLETE); assertThat(result.decision()).isEqualTo(RiskDecision.STEP_UP_MFA);
        evidence("WRONGTYPE read => " + result);
    }
    @Test void validLongMaximumReadIsHighRiskRatherThanOverflow() {
        seed(subject("subject1"), Long.toString(Long.MAX_VALUE)); seed(ip("203.0.113.10"), "0");
        var result = RedisRiskHarness.evaluate(store());
        assertThat(result.dataStatus()).isEqualTo(RiskDataStatus.COMPLETE); assertThat(result.decision()).isEqualTo(RiskDecision.STEP_UP_MFA);
        assertThat(result.reasons()).contains(RiskReason.EXCESSIVE_AUTHENTICATION_FAILURES);
    }
    @ParameterizedTest(name = "increment must not launder negative {0} counter into complete/ALLOW")
    @ValueSource(strings = {"subject", "ip"})
    void incrementMustNotTurnKnownCorruptionIntoSafeCompleteHistory(String scope) {
        track("launder", "subject1", "203.0.113.10");
        seed(scope.equals("subject") ? subject("subject1") : ip("203.0.113.10"), "-1");
        assertThat(new AuthenticationHistoryRiskCalculator(store(), thresholds(), new com.zerotrust.risk.config.RiskPolicyProperties()).calculate(RedisRiskHarness.context())).isEmpty();
        Throwable error = catchThrowable(() -> store().recordFailure("launder", "subject1", "203.0.113.10"));
        var result = RedisRiskHarness.evaluate(store());
        evidence("Negative " + scope + " before write=-1, after=" + get(scope.equals("subject") ? subject("subject1") : ip("203.0.113.10")) + " exception=" + error + " result=" + result);
        SoftAssertions softly = new SoftAssertions();
        softly.assertThat(error).as("Write path must reject a counter the read path identifies as invalid").isInstanceOf(DataAccessException.class);
        softly.assertThat(result.dataStatus()).isEqualTo(RiskDataStatus.INCOMPLETE);
        softly.assertThat(result.decision()).as("Corrupt history must not become ALLOW after losing the event").isNotEqualTo(RiskDecision.ALLOW);
        softly.assertAll();
    }
    @Test void validAbsentKeysRepresentZeroEventsInFreshWindow() {
        subject("subject1"); ip("203.0.113.10");
        var result = RedisRiskHarness.evaluate(store());
        assertThat(result.dataStatus()).isEqualTo(RiskDataStatus.COMPLETE); assertThat(result.decision()).isEqualTo(RiskDecision.ALLOW);
        evidence("Absent QA keys with reachable Redis => valid fresh-window zero, " + result);
    }
}
