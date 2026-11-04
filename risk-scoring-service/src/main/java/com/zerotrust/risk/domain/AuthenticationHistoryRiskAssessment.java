package com.zerotrust.risk.domain;

import java.math.BigDecimal;
import java.util.Objects;

public record AuthenticationHistoryRiskAssessment(
        BigDecimal riskScore,
        boolean highRisk,
        Evidence evidence
) {
    public record Evidence(long subjectFailures, long sourceIpFailures, long subjectMediumMinimum,
                           long subjectHighMinimum, long sourceIpMediumMinimum, long sourceIpHighMinimum,
                           Long failureWindowSeconds) {}

    public AuthenticationHistoryRiskAssessment(BigDecimal riskScore, boolean highRisk) {
        this(riskScore, highRisk, null);
    }
    public AuthenticationHistoryRiskAssessment {
        Objects.requireNonNull(riskScore, "riskScore must not be null");
        if (riskScore.compareTo(BigDecimal.ZERO) < 0
                || riskScore.compareTo(BigDecimal.valueOf(100)) > 0) {
            throw new IllegalArgumentException("riskScore must be between 0 and 100");
        }
    }
}
