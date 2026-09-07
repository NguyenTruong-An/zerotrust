package com.zerotrust.keycloak.risk.context;

import com.zerotrust.keycloak.risk.dto.RiskEvaluationRequest;
import org.keycloak.authentication.AuthenticationFlowContext;

public interface LoginContextExtractor {

    RiskEvaluationRequest extract(AuthenticationFlowContext context);
}
