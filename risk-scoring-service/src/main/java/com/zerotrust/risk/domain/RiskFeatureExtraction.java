package com.zerotrust.risk.domain;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

public record RiskFeatureExtraction(
        RiskFactors factors,
        RiskDataStatus dataStatus,
        List<RiskReason> reasons,
        Optional<RiskReason> priorityViolation
) {
    public RiskFeatureExtraction {
        reasons = List.copyOf(reasons);
        priorityViolation = Objects.requireNonNull(
                priorityViolation,
                "priorityViolation must not be null"
        );
    }

    public RiskFeatureExtraction(
            RiskFactors factors,
            RiskDataStatus dataStatus,
            List<RiskReason> reasons
    ) {
        this(factors, dataStatus, reasons, Optional.empty());
    }
}
