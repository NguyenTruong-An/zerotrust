package com.zerotrust.risk.rule;

import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.RiskReason;

import java.util.Optional;

public interface PrioritySecurityRule {

    Optional<RiskReason> evaluate(LoginContext context);
}
