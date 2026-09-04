package com.zerotrust.risk.domain;

import java.math.BigDecimal;
import java.util.Objects;

public record RiskFactors(
        BigDecimal deviceRisk,
        BigDecimal networkRisk,
        BigDecimal temporalRisk,
        BigDecimal authenticationHistoryRisk
) {
    private static final BigDecimal MINIMUM_SCORE = BigDecimal.ZERO;
    private static final BigDecimal MAXIMUM_SCORE = new BigDecimal("100");

    public RiskFactors {
        validateScore(deviceRisk, "deviceRisk");
        validateScore(networkRisk, "networkRisk");
        validateScore(temporalRisk, "temporalRisk");
        validateScore(authenticationHistoryRisk, "authenticationHistoryRisk");
    }

    private static void validateScore(BigDecimal value, String name) {
        Objects.requireNonNull(value, name + " must not be null");
        if (value.compareTo(MINIMUM_SCORE) < 0 || value.compareTo(MAXIMUM_SCORE) > 0) {
            throw new IllegalArgumentException(name + " must be between 0 and 100");
        }
    }
}
