package com.zerotrust.risk.audit.http;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfSystemProperty(named = "qa.http.audit", matches = "true")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class RiskIpv6HttpRegressionTests extends HttpAuditSupport {

    @AfterAll
    static void closeJwksFixture() {
        HttpJwtFixture.JWKS.stop(0);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "2001:db8::c000:201", "2001:db8::192.0.2.1",
            "2001:0db8:0000:0000:0000:0000:c000:0201",
            "2001:db8:0:0:0:0:192.0.2.1", "2001:DB8::C000:0201",
            "2001:db8::192.000.002.001"
    })
    void equivalentIpv6SpellingsKeepCompleteWeightedDeny(String input) throws Exception {
        String subject = id(); history(subject, 0); subjects.put(subject, 5L);
        var response = post(EVAL, allowed(EVAL), evaluation(subject, input));
        assertThat(response.statusCode()).isEqualTo(200);
        var result = node(response);
        assertThat(result.path("decision").asText()).isEqualTo("DENY");
        assertThat(result.path("dataStatus").asText()).isEqualTo("COMPLETE");
        assertThat(result.path("riskScore").decimalValue()).isEqualByComparingTo("90.00");
        assertThat(result.path("reasons").toString()).contains("HIGH_RISK_NETWORK");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {
            " ", "\t", "localhost", "example.invalid", "2001:::1", "2001:db8::192.0.2",
            "2001:db8::256.0.2.1", "::ffff:192.0.2.1", "::ffff:c000:201",
            "fe80::1%eth0", "fe80::1%1", "[2001:db8::1]", " 2001:db8::1", "2001:db8::1 ",
            "2001:db8:0:0:0:0:0:0:1"
    })
    void invalidIpStringsRemain400WithoutSqlOrRedisMutation(String input) throws Exception {
        var before = db();
        var body = new HashMap<String, Object>(Map.of("subjectId", id(), "authenticationSessionId", "qa-session",
                "clientId", CLIENT, "deviceId", DEVICE));
        body.put("ipAddress", input);
        var response = post(EVAL, allowed(EVAL), json(body));
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(node(response).path("fieldErrors").has("ipAddress")).isTrue();
        unchanged(before);
    }

    @Test
    void outsideHighCidrEquivalentInputsKeepTheDefaultNetworkContribution() throws Exception {
        String subject = id(); history(subject, 0); subjects.put(subject, 5L);
        for (String input : new String[]{"2001:db9::c000:201", "2001:db9::192.0.2.1"}) {
            var response = post(EVAL, allowed(EVAL), evaluation(subject, input));
            assertThat(response.statusCode()).isEqualTo(200);
            var result = node(response);
            assertThat(result.path("decision").asText()).isEqualTo("DENY");
            assertThat(result.path("dataStatus").asText()).isEqualTo("COMPLETE");
            assertThat(result.path("riskScore").decimalValue()).isEqualByComparingTo("77.50");
            assertThat(result.path("reasons").toString()).doesNotContain("HIGH_RISK_NETWORK");
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"10.1.2.3", "010.001.002.003"})
    void trustedIpv4KeepsTheExistingAllowResult(String input) throws Exception {
        String subject = id(); history(subject, 6); trusted(subject);
        var response = post(EVAL, allowed(EVAL), evaluation(subject, input));
        assertThat(response.statusCode()).isEqualTo(200);
        var result = node(response);
        assertThat(result.path("decision").asText()).isEqualTo("ALLOW");
        assertThat(result.path("dataStatus").asText()).isEqualTo("COMPLETE");
        assertThat(result.path("riskScore").decimalValue()).isEqualByComparingTo("0");
    }
}
