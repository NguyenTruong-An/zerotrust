package com.zerotrust.risk.service;

import java.math.BigDecimal;
import java.math.MathContext;
import java.util.Objects;

/** Pure B1 normalization. No I/O, state updates, threshold classification or MFA policy. */
public final class BehavioralRiskNormalizer {
    private static final BigDecimal HALF_RANGE = new BigDecimal("50");
    // Repeating rational values retain 34 significant digits; only the final weighted score
    // is quantized to cents by RiskScoringService. Never use binary floating-point here.
    private static final MathContext PRECISION = MathContext.DECIMAL128;

    private BehavioralRiskNormalizer() { }

    public static BigDecimal failureRisk(long count, long medium, long high) {
        if (count < 0 || medium <= 0 || high <= medium) {
            throw new IllegalArgumentException("Invalid failure normalization inputs");
        }
        if (count >= high) return new BigDecimal("100");
        if (count <= medium) {
            return HALF_RANGE.multiply(BigDecimal.valueOf(count))
                    .divide(BigDecimal.valueOf(medium), PRECISION);
        }
        return HALF_RANGE.add(HALF_RANGE.multiply(BigDecimal.valueOf(count - medium))
                .divide(BigDecimal.valueOf(high - medium), PRECISION));
    }

    public static BigDecimal temporalRisk(long dayMatches, long hourMatches, int size,
                                          BigDecimal dayMinimum, BigDecimal hourMinimum) {
        if (size <= 0 || dayMatches < 0 || hourMatches < 0 || dayMatches > size || hourMatches > size) {
            throw new IllegalArgumentException("Invalid temporal normalization inputs");
        }
        return deficit(dayMatches, size, dayMinimum)
                .add(deficit(hourMatches, size, hourMinimum)).multiply(HALF_RANGE);
    }

    private static BigDecimal deficit(long matches, int size, BigDecimal minimum) {
        Objects.requireNonNull(minimum, "minimum frequency must be present");
        if (minimum.signum() <= 0 || minimum.compareTo(BigDecimal.ONE) > 0) {
            throw new IllegalArgumentException("Minimum frequency must be in (0, 1]");
        }
        // Compare integer matches with tau*n before dividing: no rounded probability
        // may accidentally cross an exact frequency boundary.
        BigDecimal expected = minimum.multiply(BigDecimal.valueOf(size));
        BigDecimal shortfall = expected.subtract(BigDecimal.valueOf(matches));
        return shortfall.signum() <= 0 ? BigDecimal.ZERO : shortfall.divide(expected, PRECISION);
    }
}
