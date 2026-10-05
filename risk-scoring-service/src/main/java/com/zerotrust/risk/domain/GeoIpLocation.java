package com.zerotrust.risk.domain;

import java.util.Locale;

public record GeoIpLocation(
        String countryCode,
        String cityName,
        String timeZone,
        Integer accuracyRadiusKm,
        Long autonomousSystemNumber,
        String autonomousSystemOrganization
) {
    public GeoIpLocation {
        countryCode = normalizeCountryCode(countryCode);
        cityName = normalizeOptional(cityName);
        timeZone = normalizeOptional(timeZone);
        autonomousSystemOrganization = normalizeOptional(autonomousSystemOrganization);
        if (accuracyRadiusKm != null && accuracyRadiusKm < 0) {
            throw new IllegalArgumentException("accuracyRadiusKm must not be negative");
        }
        if (autonomousSystemNumber != null && autonomousSystemNumber < 0) {
            throw new IllegalArgumentException("autonomousSystemNumber must not be negative");
        }
    }

    private static String normalizeCountryCode(String value) {
        String normalized = normalizeOptional(value);
        if (normalized == null) {
            return null;
        }
        normalized = normalized.toUpperCase(Locale.ROOT);
        if (!normalized.matches("[A-Z]{2}")) {
            throw new IllegalArgumentException("countryCode must use ISO 3166-1 alpha-2 format");
        }
        return normalized;
    }

    private static String normalizeOptional(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
