package com.zerotrust.keycloak.risk.policy;

import com.zerotrust.keycloak.risk.dto.RiskDataStatus;
import com.zerotrust.keycloak.risk.dto.RiskDecision;
import com.zerotrust.keycloak.risk.dto.RiskEvaluationResponse;
import com.zerotrust.keycloak.risk.dto.RiskLevel;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RiskDecisionHandlerTest {

    private final RiskDecisionHandler handler = new RiskDecisionHandler();

    @Test
    void allowsLowRiskAuthentication() {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        when(context.getAuthenticationSession()).thenReturn(session);

        handler.handle(context, evaluation(RiskDecision.ALLOW));

        verify(context).success();
        verify(session, never()).setAuthNote(
                RiskAuthenticationNotes.STEP_UP_REQUIRED,
                Boolean.TRUE.toString()
        );
        verify(session).setAuthNote(RiskAuthenticationNotes.DECISION, RiskDecision.ALLOW.name());
    }

    @Test
    void marksAuthenticationForConditionalMfa() {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        when(context.getAuthenticationSession()).thenReturn(session);

        handler.handle(context, evaluation(RiskDecision.STEP_UP_MFA));

        verify(session).setAuthNote(
                RiskAuthenticationNotes.STEP_UP_REQUIRED,
                Boolean.TRUE.toString()
        );
        verify(context).success();
    }

    @Test
    void deniesAuthenticationWithoutExposingRiskDetails() {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        LoginFormsProvider forms = mock(LoginFormsProvider.class);
        Response errorPage = mock(Response.class);
        when(context.getAuthenticationSession()).thenReturn(session);
        when(context.form()).thenReturn(forms);
        when(forms.setError("accessDenied")).thenReturn(forms);
        when(forms.createErrorPage(Response.Status.FORBIDDEN)).thenReturn(errorPage);

        handler.handle(context, evaluation(RiskDecision.DENY));

        verify(context).failure(
                eq(AuthenticationFlowError.ACCESS_DENIED),
                eq(errorPage),
                eq("risk_policy_denied"),
                eq("accessDenied")
        );
        verify(context, never()).success();
    }

    @Test
    void failsClosedWhenRiskServiceIsUnavailableByDefault() {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        LoginFormsProvider forms = mock(LoginFormsProvider.class);
        Response errorPage = mock(Response.class);
        when(context.getAuthenticationSession()).thenReturn(session);
        when(context.form()).thenReturn(forms);
        when(forms.setError("accessDenied")).thenReturn(forms);
        when(forms.createErrorPage(Response.Status.FORBIDDEN)).thenReturn(errorPage);

        handler.handleUnavailable(context, RiskFailureMode.DENY, "TIMEOUT");

        verify(session).setAuthNote(RiskAuthenticationNotes.FAILURE_TYPE, "TIMEOUT");
        verify(context).failure(
                eq(AuthenticationFlowError.ACCESS_DENIED),
                eq(errorPage),
                eq("risk_policy_denied"),
                eq("accessDenied")
        );
    }

    private static RiskEvaluationResponse evaluation(RiskDecision decision) {
        RiskLevel riskLevel = switch (decision) {
            case ALLOW -> RiskLevel.LOW;
            case STEP_UP_MFA -> RiskLevel.MEDIUM;
            case DENY -> RiskLevel.HIGH;
        };
        return new RiskEvaluationResponse(
                UUID.fromString("0ea3026d-2f0a-4ab8-a45e-8183e47f52e5"),
                "user-1",
                "root-session:tab-1",
                BigDecimal.TEN,
                riskLevel,
                decision,
                RiskDataStatus.COMPLETE,
                List.of(),
                Instant.parse("2026-09-04T08:00:00Z")
        );
    }
}
