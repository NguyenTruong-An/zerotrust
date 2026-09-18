package com.zerotrust.keycloak.risk.policy;

import com.zerotrust.keycloak.risk.dto.RiskDecision;
import com.zerotrust.keycloak.risk.dto.RiskEvaluationResponse;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Objects;

public final class RiskDecisionHandler {

    private static final String ACCESS_DENIED_MESSAGE = "accessDenied";

    public void handle(
            AuthenticationFlowContext context,
            RiskEvaluationResponse evaluation
    ) {
        Objects.requireNonNull(context, "context must not be null");
        Objects.requireNonNull(evaluation, "evaluation must not be null");

        AuthenticationSessionModel session = context.getAuthenticationSession();
        RiskAuthenticationNotes.clear(session);
        session.setAuthNote(RiskAuthenticationNotes.DECISION, evaluation.decision().name());
        session.setAuthNote(
                RiskAuthenticationNotes.EVALUATION_ID,
                evaluation.evaluationId().toString()
        );
        session.setAuthNote(RiskAuthenticationNotes.RISK_LEVEL, evaluation.riskLevel().name());
        session.setAuthNote(RiskAuthenticationNotes.DATA_STATUS, evaluation.dataStatus().name());

        if (evaluation.decision() == RiskDecision.ALLOW) {
            context.success();
        } else if (evaluation.decision() == RiskDecision.STEP_UP_MFA) {
            requireStepUp(session);
            session.setAuthNote(
                    RiskAuthenticationNotes.TRUST_DEVICE_ELIGIBLE,
                    Boolean.TRUE.toString()
            );
            context.success();
        } else {
            deny(context);
        }
    }

    public void handleUnavailable(
            AuthenticationFlowContext context,
            RiskFailureMode failureMode,
            String failureType
    ) {
        Objects.requireNonNull(context, "context must not be null");
        Objects.requireNonNull(failureMode, "failureMode must not be null");

        AuthenticationSessionModel session = context.getAuthenticationSession();
        RiskAuthenticationNotes.clear(session);
        if (failureType != null) {
            session.setAuthNote(RiskAuthenticationNotes.FAILURE_TYPE, failureType);
        }

        if (failureMode == RiskFailureMode.STEP_UP_MFA) {
            session.setAuthNote(RiskAuthenticationNotes.DECISION, RiskDecision.STEP_UP_MFA.name());
            requireStepUp(session);
            context.success();
        } else {
            session.setAuthNote(RiskAuthenticationNotes.DECISION, RiskDecision.DENY.name());
            deny(context);
        }
    }

    private static void requireStepUp(AuthenticationSessionModel session) {
        session.setAuthNote(RiskAuthenticationNotes.STEP_UP_REQUIRED, Boolean.TRUE.toString());
    }

    private static void deny(AuthenticationFlowContext context) {
        Response response = context.form()
                .setError(ACCESS_DENIED_MESSAGE)
                .createErrorPage(Response.Status.FORBIDDEN);
        context.failure(
                AuthenticationFlowError.ACCESS_DENIED,
                response,
                "risk_policy_denied",
                ACCESS_DENIED_MESSAGE
        );
    }
}
