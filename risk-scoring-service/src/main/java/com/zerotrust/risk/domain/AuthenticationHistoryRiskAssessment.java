package com.zerotrust.risk.domain;

import java.math.BigDecimal;
import java.util.Objects;

public record AuthenticationHistoryRiskAssessment(
        BigDecimal riskScore,
        boolean highRisk
) {
    public AuthenticationHistoryRiskAssessment {
        Objects.requireNonNull(riskScore, "riskScore must not be null");
        if (riskScore.compareTo(BigDecimal.ZERO) < 0
                || riskScore.compareTo(BigDecimal.valueOf(100)) > 0) {
            throw new IllegalArgumentException("riskScore must be between 0 and 100");
        }
    }
}
