package com.zerotrust.risk.domain;

import java.util.List;

public record RiskFeatureExtraction(
        RiskFactors factors,
        RiskDataStatus dataStatus,
        List<RiskReason> reasons
) {
    public RiskFeatureExtraction {
        reasons = List.copyOf(reasons);
    }
}
