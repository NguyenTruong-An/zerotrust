package com.zerotrust.risk.domain;

/** Allowlisted calculation evidence. Deliberately excludes context, identifiers, IPs and device hashes. */
public record RiskSignalSnapshot(
        DeviceRecognition.Reason deviceReason,
        NetworkRiskAssessment network,
        TemporalRiskAssessment.Evidence temporal,
        AuthenticationHistoryRiskAssessment.Evidence authenticationHistory
) {}
