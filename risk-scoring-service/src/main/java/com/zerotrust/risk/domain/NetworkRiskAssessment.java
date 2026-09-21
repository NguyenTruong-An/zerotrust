package com.zerotrust.risk.domain;

import java.math.BigDecimal;
import java.util.Objects;

public record NetworkRiskAssessment(
        NetworkRiskStatus status,
        BigDecimal riskScore
) {
    private static final BigDecimal MINIMUM_SCORE = BigDecimal.ZERO;
    private static final BigDecimal MAXIMUM_SCORE = new BigDecimal("100");

    public NetworkRiskAssessment {
        Objects.requireNonNull(status, "status must not be null");
        if (status == NetworkRiskStatus.AVAILABLE) {
            Objects.requireNonNull(riskScore, "riskScore must be present when network risk is available");
            if (riskScore.compareTo(MINIMUM_SCORE) < 0
                    || riskScore.compareTo(MAXIMUM_SCORE) > 0) {
                throw new IllegalArgumentException("riskScore must be between 0 and 100");
            }
        } else if (riskScore != null) {
            throw new IllegalArgumentException("riskScore must be absent when network risk is unavailable");
        }
    }

    public static NetworkRiskAssessment available(BigDecimal riskScore) {
        return new NetworkRiskAssessment(NetworkRiskStatus.AVAILABLE, riskScore);
    }

    public static NetworkRiskAssessment unavailable() {
        return new NetworkRiskAssessment(NetworkRiskStatus.UNAVAILABLE, null);
    }
}
