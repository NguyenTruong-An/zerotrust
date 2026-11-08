package com.zerotrust.keycloak.risk.client;

import com.zerotrust.keycloak.risk.dto.*;
import java.math.BigDecimal;

/** Validate the wire contract, never calculate risk or replace the Risk Service's policy. */
final class RiskResponseContract {
    private RiskResponseContract() { }

    static void validate(RiskEvaluationResponse response) {
        boolean coherent = switch (response.decision()) {
            case ALLOW -> response.riskLevel() == RiskLevel.LOW && response.dataStatus() == RiskDataStatus.COMPLETE;
            case STEP_UP_MFA -> response.riskLevel() == RiskLevel.MEDIUM
                    && response.dataStatus() != RiskDataStatus.NOT_EVALUATED;
            case DENY -> response.riskLevel() == RiskLevel.HIGH
                    && response.dataStatus() != RiskDataStatus.INCOMPLETE;
        };
        BigDecimal score = response.riskScore();
        boolean validScore = response.dataStatus() == RiskDataStatus.COMPLETE
                ? score != null && score.signum() >= 0 && score.compareTo(BigDecimal.valueOf(100)) <= 0
                    && score.stripTrailingZeros().scale() <= 2
                : score == null;
        if (!coherent || !validScore || response.subjectId().isBlank()
                || response.authenticationSessionId().isBlank()
                || response.trustGeneration() != null && response.trustGeneration() < 0) {
            throw RiskScoringClientException.invalidResponse("Risk response violates the decision contract", null);
        }
    }
}
