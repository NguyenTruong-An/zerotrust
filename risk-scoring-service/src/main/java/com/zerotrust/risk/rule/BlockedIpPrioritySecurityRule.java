package com.zerotrust.risk.rule;

import com.zerotrust.risk.config.RiskPolicyProperties;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.RiskReason;
import com.zerotrust.risk.validation.IpAddressNormalizer;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class BlockedIpPrioritySecurityRule implements PrioritySecurityRule {

    private final Set<String> blockedIpAddresses;

    public BlockedIpPrioritySecurityRule(RiskPolicyProperties properties) {
        this.blockedIpAddresses = properties.getPriorityRules()
                .getBlockedIpAddresses()
                .stream()
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .map(IpAddressNormalizer::normalize)
                .collect(Collectors.toUnmodifiableSet());
    }

    @Override
    public Optional<RiskReason> evaluate(LoginContext context) {
        if (!blockedIpAddresses.isEmpty()
                && blockedIpAddresses.contains(IpAddressNormalizer.normalize(context.ipAddress()))) {
            return Optional.of(RiskReason.BLOCKED_IP_ADDRESS);
        }
        return Optional.empty();
    }
}
