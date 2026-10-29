package com.zerotrust.risk.domain;

/** B1 is opt-in; keeping B0 as the default preserves the deployed decision model. */
public enum RiskScoreModel {
    BASELINE_B0,
    CONTINUOUS_B1
}
