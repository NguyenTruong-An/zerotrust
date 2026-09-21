package com.zerotrust.risk.domain;

import java.math.BigDecimal;
import java.util.Objects;

public record TemporalRiskAssessment(
        TemporalProfileStatus status,
        BigDecimal riskScore
) {
    private static final BigDecimal MINIMUM_SCORE = BigDecimal.ZERO;
    private static final BigDecimal MAXIMUM_SCORE = new BigDecimal("100");

    public TemporalRiskAssessment {
        Objects.requireNonNull(status, "status must not be null");
        if (status == TemporalProfileStatus.AVAILABLE) {
            Objects.requireNonNull(riskScore, "available assessment must have a risk score");
            if (riskScore.compareTo(MINIMUM_SCORE) < 0
                    || riskScore.compareTo(MAXIMUM_SCORE) > 0) {
                throw new IllegalArgumentException("riskScore must be between 0 and 100");
            }
        } else if (riskScore != null) {
            throw new IllegalArgumentException(
                    "non-available temporal assessment must not have a risk score"
            );
        }
    }

    public static TemporalRiskAssessment available(BigDecimal riskScore) {
        return new TemporalRiskAssessment(TemporalProfileStatus.AVAILABLE, riskScore);
    }

    public static TemporalRiskAssessment coldStart() {
        return new TemporalRiskAssessment(TemporalProfileStatus.COLD_START, null);
    }

    public static TemporalRiskAssessment unavailable() {
        return new TemporalRiskAssessment(TemporalProfileStatus.UNAVAILABLE, null);
    }
}
