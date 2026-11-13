package com.zerotrust.risk.networkv2;

/** No raw IP, device, city, token, or user-agent is retained. */
public record NetworkObservation(String country, Long asn, String networkHash,
                                 Integer accuracyRadiusKm, Quality quality) {
    public enum Quality { COUNTRY_ASN, COARSE_LOCATION, UNKNOWN_ACCURACY, PARTIAL,
        NON_PUBLIC, GEOIP_DISABLED, GEOIP_UNAVAILABLE, NO_RECORD }

    public boolean complete() {
        return country != null && asn != null && asn > 0 && networkHash != null;
    }
}
