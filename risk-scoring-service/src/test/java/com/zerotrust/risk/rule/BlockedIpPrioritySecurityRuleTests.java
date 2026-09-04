package com.zerotrust.risk.rule;

import com.zerotrust.risk.config.RiskPolicyProperties;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.RiskReason;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

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
