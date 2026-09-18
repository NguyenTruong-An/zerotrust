package com.zerotrust.keycloak.risk.policy;

import org.keycloak.sessions.AuthenticationSessionModel;

public final class RiskAuthenticationNotes {

    public static final String STEP_UP_REQUIRED = "zerotrust.risk.step-up-required";
    public static final String DECISION = "zerotrust.risk.decision";
    public static final String EVALUATION_ID = "zerotrust.risk.evaluation-id";
    public static final String RISK_LEVEL = "zerotrust.risk.level";
    public static final String DATA_STATUS = "zerotrust.risk.data-status";
    public static final String FAILURE_TYPE = "zerotrust.risk.failure-type";
    public static final String TRUST_DEVICE_ELIGIBLE = "zerotrust.risk.trust-device-eligible";
    public static final String EVALUATOR_CONFIG_ID = "zerotrust.risk.evaluator-config-id";

    private RiskAuthenticationNotes() {
    }

    public static void clear(AuthenticationSessionModel session) {
        session.removeAuthNote(STEP_UP_REQUIRED);
        session.removeAuthNote(DECISION);
        session.removeAuthNote(EVALUATION_ID);
        session.removeAuthNote(RISK_LEVEL);
        session.removeAuthNote(DATA_STATUS);
        session.removeAuthNote(FAILURE_TYPE);
        session.removeAuthNote(TRUST_DEVICE_ELIGIBLE);
        session.removeAuthNote(EVALUATOR_CONFIG_ID);
    }
}
