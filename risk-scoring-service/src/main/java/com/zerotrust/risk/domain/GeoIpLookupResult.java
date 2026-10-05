package com.zerotrust.risk.domain;

import java.util.Objects;

public record GeoIpLookupResult(
        GeoIpLookupStatus status,
        GeoIpLocation location
) {
    public GeoIpLookupResult {
        Objects.requireNonNull(status, "status must not be null");
        if (status == GeoIpLookupStatus.AVAILABLE) {
            Objects.requireNonNull(location, "location must be present when Geo-IP is available");
        } else if (location != null) {
            throw new IllegalArgumentException("location must be absent when Geo-IP is not available");
        }
    }

    public static GeoIpLookupResult available(GeoIpLocation location) {
        return new GeoIpLookupResult(GeoIpLookupStatus.AVAILABLE, location);
    }

    public static GeoIpLookupResult notFound() {
        return new GeoIpLookupResult(GeoIpLookupStatus.NOT_FOUND, null);
    }

    public static GeoIpLookupResult unavailable() {
        return new GeoIpLookupResult(GeoIpLookupStatus.UNAVAILABLE, null);
    }

    public static GeoIpLookupResult disabled() {
        return new GeoIpLookupResult(GeoIpLookupStatus.DISABLED, null);
    }
}
