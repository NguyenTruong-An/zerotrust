package com.zerotrust.risk.domain;

import java.util.Objects;

/** Allowlisted metadata only. Missing identifier is an observed device state, not an I/O outage. */
public record RiskFeatureEvidence(
        Status device,
        Status network,
        Status temporal,
        Status authenticationHistory,
        DeviceRecognitionStatus deviceState,
        NetworkRiskSource networkSource
) {
    public enum Status { AVAILABLE, COLD_START, UNAVAILABLE, NOT_OBSERVED }

    public RiskFeatureEvidence {
        Objects.requireNonNull(device);
        Objects.requireNonNull(network);
        Objects.requireNonNull(temporal);
        Objects.requireNonNull(authenticationHistory);
    }

    public static RiskFeatureEvidence notObserved() {
        return new RiskFeatureEvidence(Status.NOT_OBSERVED, Status.NOT_OBSERVED,
                Status.NOT_OBSERVED, Status.NOT_OBSERVED, null, null);
    }
}
