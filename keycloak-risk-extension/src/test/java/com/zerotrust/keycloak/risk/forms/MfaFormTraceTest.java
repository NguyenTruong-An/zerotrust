package com.zerotrust.keycloak.risk.forms;

import com.zerotrust.keycloak.risk.trace.RiskEvaluationTrace;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.keycloak.forms.login.LoginFormsPages;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakContext;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class MfaFormTraceTest {
    @Test
    void renderedChallengeIsNotMfaCompletionAndInvalidOtpIsExplicitlyRejected() {
        Fixture f = new Fixture();
        f.provider.traceMfaForm(LoginFormsPages.LOGIN_TOTP, f.ok);
        assertEquals(1, f.lines.size());
        assertTrue(f.lines.get(0).contains("CHALLENGE_RENDERED"));
        assertFalse(f.lines.get(0).contains("MFA_COMPLETED"));
        f.provider.setError(Messages.INVALID_TOTP);
        f.provider.traceMfaForm(LoginFormsPages.LOGIN_TOTP, f.ok);
        assertEquals(3, f.lines.size());
        assertTrue(f.lines.get(2).contains("MFA_INPUT_REJECTED"));
    }

    @Test
    void failedRenderOrOrdinaryLoginDoesNotClaimMfaChallenge() {
        Fixture f = new Fixture();
        Response failed = mock(Response.class); when(failed.getStatus()).thenReturn(500);
        f.provider.traceMfaForm(LoginFormsPages.LOGIN_TOTP, failed);
        f.provider.traceMfaForm(LoginFormsPages.LOGIN, f.ok);
        assertTrue(f.lines.isEmpty());
        f.provider.traceMfaForm(LoginFormsPages.LOGIN_RECOVERY_AUTHN_CODES_INPUT, f.ok);
        assertEquals(1, f.lines.size());
    }

    @Test
    void sinkFailureDoesNotChangeFormOrErrorMessage() {
        Fixture f = new Fixture();
        InspectableProvider provider = new InspectableProvider(sessionWithContext(),
                new RiskEvaluationTrace(line -> { throw new IllegalStateException("sink unavailable"); }, new byte[32], Clock.systemUTC()));
        provider.setAuthenticationSession(f.auth);
        provider.setError(Messages.INVALID_TOTP);
        assertDoesNotThrow(() -> provider.traceMfaForm(LoginFormsPages.LOGIN_TOTP, f.ok));
        assertEquals(Messages.INVALID_TOTP, provider.errorMessage());
    }

    private static final class Fixture {
        final List<String> lines = new ArrayList<>();
        final AuthenticationSessionModel auth = mock(AuthenticationSessionModel.class);
        final ZeroTrustLoginFormsProvider provider = new ZeroTrustLoginFormsProvider(sessionWithContext(),
                new RiskEvaluationTrace(lines::add, new byte[32], Clock.systemUTC()));
        final Response ok = mock(Response.class);
        Fixture() {
            when(auth.getAuthNote(RiskEvaluationTrace.TRACE_ID)).thenReturn("9c258b85-50c8-4c7f-85ac-c75d82786877");
            when(ok.getStatus()).thenReturn(200);
            provider.setAuthenticationSession(auth);
        }
    }

    private static final class InspectableProvider extends ZeroTrustLoginFormsProvider {
        InspectableProvider(KeycloakSession session, RiskEvaluationTrace trace) { super(session, trace); }
        String errorMessage() { return getFirstMessageUnformatted(); }
    }

    private static KeycloakSession sessionWithContext() {
        KeycloakSession session = mock(KeycloakSession.class);
        when(session.getContext()).thenReturn(mock(KeycloakContext.class));
        return session;
    }
}
