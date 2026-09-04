package com.zerotrust.risk.rule;

import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.RiskReason;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

@Component
public class PrioritySecurityRuleEvaluator {

    private final List<PrioritySecurityRule> rules;

    public PrioritySecurityRuleEvaluator(List<PrioritySecurityRule> rules) {
        this.rules = List.copyOf(rules);
    }

    public Optional<RiskReason> firstViolation(LoginContext context) {
        return rules.stream()
                .map(rule -> rule.evaluate(context))
                .flatMap(Optional::stream)
                .findFirst();
    }
}
