package com.zerotrust.keycloak.risk.client;

import com.zerotrust.keycloak.risk.dto.RiskEvaluationRequest;
import com.zerotrust.keycloak.risk.dto.RiskEvaluationResponse;

public interface RiskScoringClient {

    RiskEvaluationResponse evaluate(RiskEvaluationRequest request);
}
