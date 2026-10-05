package com.zerotrust.risk.rule;

import com.zerotrust.risk.config.RiskPolicyProperties;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.RiskReason;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BlockedIpPrioritySecurityRuleTests {

    @Test
    void blocksConfiguredIpAddress() {
        BlockedIpPrioritySecurityRule rule = ruleWithBlockedIps("203.0.113.10");

        assertThat(rule.evaluate(context("203.0.113.10")))
                .contains(RiskReason.BLOCKED_IP_ADDRESS);
    }

    @Test
    void ignoresIpAddressThatIsNotBlocked() {
        BlockedIpPrioritySecurityRule rule = ruleWithBlockedIps("198.51.100.20");

        assertThat(rule.evaluate(context("203.0.113.10"))).isEmpty();
    }

    @ParameterizedTest
    @CsvSource({
            "2001:db8::1, 2001:db8:0:0:0:0:0:1",
            "2001:0DB8:0000:0000:0000:0000:0000:0001, 2001:db8::1",
            "2001:db8::ABCD, 2001:DB8:0:0:0:0:0:abcd",
            "::1, 0:0:0:0:0:0:0:1",
            "::, 0:0:0:0:0:0:0:0",
            "2001:db8::192.0.2.1, 2001:db8:0:0:0:0:c000:201",
            "203.0.113.10, 203.000.113.010",
            "203.000.113.010, 203.0.113.10"
    })
    void blocksEquivalentIpRepresentations(String configured, String received) {
        assertThat(ruleWithBlockedIps(configured).evaluate(context(received)))
                .contains(RiskReason.BLOCKED_IP_ADDRESS);
    }

    @Test
    void doesNotBlockANeighboringIpv6Address() {
        assertThat(ruleWithBlockedIps("2001:db8::1").evaluate(context("2001:db8::2")))
                .isEmpty();
    }

    @Test
    void ignoresEmptyConfigurationEntriesAndTrimsConfiguredAddresses() {
        assertThat(ruleWithBlockedIps("", " ", " 2001:db8::1 ")
                .evaluate(context("2001:db8:0:0:0:0:0:1")))
                .contains(RiskReason.BLOCKED_IP_ADDRESS);
    }

    @Test
    void rejectsAnInvalidBlocklistAtStartup() {
        assertThatThrownBy(() -> ruleWithBlockedIps("example.invalid"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private BlockedIpPrioritySecurityRule ruleWithBlockedIps(String... addresses) {
        RiskPolicyProperties properties = new RiskPolicyProperties();
        RiskPolicyProperties.PriorityRules rules = new RiskPolicyProperties.PriorityRules();
        rules.setBlockedIpAddresses(List.of(addresses));
        properties.setPriorityRules(rules);
        return new BlockedIpPrioritySecurityRule(properties);
    }

    private LoginContext context(String ipAddress) {
        return new LoginContext(
                "subject-id",
                "authentication-session-id",
                "zerotrust-spa",
                ipAddress,
                "Mozilla/5.0",
                "device-123",
                Instant.parse("2026-09-04T08:00:00Z")
        );
    }
}
