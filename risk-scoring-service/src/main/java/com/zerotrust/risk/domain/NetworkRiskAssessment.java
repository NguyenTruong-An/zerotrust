package com.zerotrust.risk.domain;

import java.math.BigDecimal;
import java.util.Objects;

public record NetworkRiskAssessment(
        NetworkRiskStatus status,
        BigDecimal riskScore,
        NetworkRiskBand band,
        NetworkRiskSource source,
        GeoIpLocation geoIpLocation,
        NetworkRiskUnavailableReason unavailableReason
) {
    private static final BigDecimal MINIMUM_SCORE = BigDecimal.ZERO;
    private static final BigDecimal MAXIMUM_SCORE = new BigDecimal("100");

    public NetworkRiskAssessment {
        Objects.requireNonNull(status, "status must not be null");
        if (status == NetworkRiskStatus.AVAILABLE) {
            Objects.requireNonNull(riskScore, "riskScore must be present when network risk is available");
            Objects.requireNonNull(band, "band must be present when network risk is available");
            Objects.requireNonNull(source, "source must be present when network risk is available");
            if (riskScore.compareTo(MINIMUM_SCORE) < 0
                    || riskScore.compareTo(MAXIMUM_SCORE) > 0) {
                throw new IllegalArgumentException("riskScore must be between 0 and 100");
            }
            if (source != NetworkRiskSource.GEOIP && geoIpLocation != null) {
                throw new IllegalArgumentException("Geo-IP location requires GEOIP source");
            }
            if (unavailableReason != null) {
                throw new IllegalArgumentException("unavailableReason must be absent when network risk is available");
            }
        } else {
            Objects.requireNonNull(
                    unavailableReason,
                    "unavailableReason must be present when network risk is unavailable"
            );
            if (riskScore != null || band != null || source != null || geoIpLocation != null) {
                throw new IllegalArgumentException("risk details must be absent when network risk is unavailable");
            }
        }
    }

    public static NetworkRiskAssessment available(BigDecimal riskScore) {
        return available(
                riskScore,
                NetworkRiskBand.DEFAULT,
                NetworkRiskSource.DEFAULT_POLICY,
                null
        );
    }

    public static NetworkRiskAssessment available(
            BigDecimal riskScore,
            NetworkRiskBand band,
            NetworkRiskSource source,
            GeoIpLocation geoIpLocation
    ) {
        return new NetworkRiskAssessment(
                NetworkRiskStatus.AVAILABLE,
                riskScore,
                band,
                source,
                geoIpLocation,
                null
        );
    }

    public static NetworkRiskAssessment unavailable() {
        return unavailable(NetworkRiskUnavailableReason.PROVIDER_DISABLED);
    }

    public static NetworkRiskAssessment unavailable(NetworkRiskUnavailableReason reason) {
        return new NetworkRiskAssessment(
                NetworkRiskStatus.UNAVAILABLE,
                null,
                null,
                null,
                null,
                reason
        );
    }

    public boolean requiresStepUp() {
        return status == NetworkRiskStatus.AVAILABLE && band == NetworkRiskBand.HIGH;
    }

    public boolean usesGeoIp() {
        return status == NetworkRiskStatus.AVAILABLE && source == NetworkRiskSource.GEOIP;
    }
}
