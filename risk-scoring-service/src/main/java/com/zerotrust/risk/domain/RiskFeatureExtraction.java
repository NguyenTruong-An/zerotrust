package com.zerotrust.risk.domain;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

public record RiskFeatureExtraction(
        RiskFactors factors,
        RiskDataStatus dataStatus,
        List<RiskReason> reasons,
        Optional<RiskReason> priorityViolation,
        Optional<RiskReason> mandatoryStepUpReason
) {
    public RiskFeatureExtraction {
        reasons = List.copyOf(reasons);
        priorityViolation = Objects.requireNonNull(
                priorityViolation,
                "priorityViolation must not be null"
        );
        mandatoryStepUpReason = Objects.requireNonNull(
                mandatoryStepUpReason,
                "mandatoryStepUpReason must not be null"
        );
    }

    public RiskFeatureExtraction(
            RiskFactors factors,
            RiskDataStatus dataStatus,
            List<RiskReason> reasons
    ) {
        this(factors, dataStatus, reasons, Optional.empty(), Optional.empty());
    }

    public RiskFeatureExtraction(
            RiskFactors factors,
            RiskDataStatus dataStatus,
            List<RiskReason> reasons,
            Optional<RiskReason> priorityViolation
    ) {
        this(factors, dataStatus, reasons, priorityViolation, Optional.empty());
    }
}
