package com.zerotrust.keycloak.risk.authenticator;

import com.zerotrust.keycloak.risk.policy.RiskAuthenticationNotes;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.sessions.AuthenticationSessionModel;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RiskStepUpConditionTest {

    @Test
    void matchesOnlyExplicitStepUpNote() {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        when(context.getAuthenticationSession()).thenReturn(session);
        when(session.getAuthNote(RiskAuthenticationNotes.STEP_UP_REQUIRED))
                .thenReturn("true", null, "false");

        assertTrue(RiskStepUpCondition.INSTANCE.matchCondition(context));
        assertFalse(RiskStepUpCondition.INSTANCE.matchCondition(context));
        assertFalse(RiskStepUpCondition.INSTANCE.matchCondition(context));
    }
}
