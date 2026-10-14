package com.zerotrust.risk.audit.http;

import com.zerotrust.risk.config.TemporalRiskProperties;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import java.math.BigDecimal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;

@EnabledIfSystemProperty(named = "qa.http.audit", matches = "true")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Import(HttpDispatchTrace.class)
class RiskTemporalPrecisionHttpRegressionTests extends HttpAuditSupport {
    @Autowired TemporalRiskProperties temporal;

    @AfterEach
    void restoreFixtureMinimums() {
        temporal.setMinimumDayFrequency(new BigDecimal("0.6666668"));
        temporal.setMinimumHourFrequency(new BigDecimal("0.6666668"));
    }

    @AfterAll
    static void stopJwks() {
        HttpJwtFixture.JWKS.stop(0);
    }

    @ParameterizedTest(name = "{0}/6 day={1} hour={2} score={3} decision={4}")
    @CsvSource({
            "4,0.6666668,0.6666668,50,STEP_UP_MFA,true",
            "2,0.3333332,0.3333332,25,ALLOW,false",
            "3,0.50000000000000000000000000000000000000000000000001,0.50000000000000000000000000000000000000000000000001,50,STEP_UP_MFA,true",
            "3,0.50000000000000000000000000000000000000000000000000,0.50000000000000000000000000000000000000000000000000,25,ALLOW,false",
            "0,0.10,0.20,50,STEP_UP_MFA,true",
            "1,0.10,0.20,37.50,ALLOW,true",
            "6,1,1,25,ALLOW,false"
    })
    void exactTemporalClassificationReachesSignedLiveHttpResponse(
            int matches, String day, String hour, String score, String decision, boolean temporalReason
    ) throws Exception {
        temporal.setMinimumDayFrequency(new BigDecimal(day));
        temporal.setMinimumHourFrequency(new BigDecimal(hour));
        String subject = id();
        history(subject, matches);
        trusted(subject);
        subjects.put(subject, 3L);
        System.out.println("FIX08 HTTP input=" + evaluation(subject, "203.0.113.10")
                + " dayMinimum=" + day + " hourMinimum=" + hour
                + " timestamps=" + jdbc.queryForList(
                "SELECT authenticated_at FROM authentication_success_events WHERE subject_id = ? ORDER BY authenticated_at",
                subject));
        var before = db();
        verifyNoInteractions(redis);
        var response = post(EVAL, allowed(EVAL), evaluation(subject, "203.0.113.10"));
        assertThat(response.statusCode()).isEqualTo(200);
        var result = node(response);
        assertThat(result.path("riskScore").decimalValue()).isEqualByComparingTo(score);
        assertThat(result.path("decision").asText()).isEqualTo(decision);
        assertThat(result.path("dataStatus").asText()).isEqualTo("COMPLETE");
        assertThat(result.path("reasons").toString().contains("TEMPORAL_RISK")).isEqualTo(temporalReason);
        assertThat(db()).isEqualTo(before);
        assertThat(writes.get()).isZero();
        assertThat(HttpJwtFixture.FETCHES.get()).isPositive();
    }
}
