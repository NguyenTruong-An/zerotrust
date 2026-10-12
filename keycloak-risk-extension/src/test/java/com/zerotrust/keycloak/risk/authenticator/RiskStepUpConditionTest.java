package com.zerotrust.keycloak.risk.authenticator;

import com.zerotrust.keycloak.risk.policy.RiskAuthenticationNotes;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.stream.Stream;

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

    @Test
    void defersResetUserWithoutMfaCredentialsToMandatoryTotpEnrollment() {
        Fixture fixture = new Fixture();
        fixture.pendingTotpEnrollment();

        assertFalse(RiskStepUpCondition.INSTANCE.matchCondition(fixture.context));
    }

    @Test
    void stillRequiresMfaWhenOtpCredentialExistsDespitePendingEnrollment() {
        Fixture fixture = new Fixture();
        fixture.pendingTotpEnrollment();
        when(fixture.credentials.isConfiguredFor("otp")).thenReturn(true);

        assertTrue(RiskStepUpCondition.INSTANCE.matchCondition(fixture.context));
    }

    @Test
    void stillRequiresMfaWhenRecoveryCredentialExistsDespitePendingEnrollment() {
        Fixture fixture = new Fixture();
        fixture.pendingTotpEnrollment();
        when(fixture.credentials.isConfiguredFor("recovery-authn-codes")).thenReturn(true);

        assertTrue(RiskStepUpCondition.INSTANCE.matchCondition(fixture.context));
    }

    @Test
    void missingCredentialsWithoutEnrollmentActionCannotSkipMfa() {
        Fixture fixture = new Fixture();

        assertTrue(RiskStepUpCondition.INSTANCE.matchCondition(fixture.context));
    }

    @Test
    void disabledTotpEnrollmentCannotSkipMfa() {
        Fixture fixture = new Fixture();
        fixture.pendingTotpEnrollment();
        fixture.totpAction.setEnabled(false);

        assertTrue(RiskStepUpCondition.INSTANCE.matchCondition(fixture.context));
    }

    @Test
    void missingTotpProviderCannotSkipMfa() {
        Fixture fixture = new Fixture();
        fixture.pendingTotpEnrollment();
        when(fixture.realm.getRequiredActionProviderByAlias("CONFIGURE_TOTP")).thenReturn(null);

        assertTrue(RiskStepUpCondition.INSTANCE.matchCondition(fixture.context));
    }

    @Test
    void differentProviderUsingTotpAliasCannotSkipMfa() {
        Fixture fixture = new Fixture();
        fixture.pendingTotpEnrollment();
        fixture.totpAction.setProviderId("custom-action");

        assertTrue(RiskStepUpCondition.INSTANCE.matchCondition(fixture.context));
    }

    @Test
    void unrelatedRequiredActionCannotSkipMfa() {
        Fixture fixture = new Fixture();
        when(fixture.user.getRequiredActionsStream()).thenAnswer(ignored -> Stream.of("UPDATE_PASSWORD"));

        assertTrue(RiskStepUpCondition.INSTANCE.matchCondition(fixture.context));
    }

    private static final class Fixture {
        private final AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        private final AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        private final UserModel user = mock(UserModel.class);
        private final RealmModel realm = mock(RealmModel.class);
        private final SubjectCredentialManager credentials = mock(SubjectCredentialManager.class);
        private final RequiredActionProviderModel totpAction = new RequiredActionProviderModel();

        private Fixture() {
            when(context.getAuthenticationSession()).thenReturn(session);
            when(session.getAuthNote(RiskAuthenticationNotes.STEP_UP_REQUIRED)).thenReturn("true");
            when(context.getUser()).thenReturn(user);
            when(context.getRealm()).thenReturn(realm);
            when(user.credentialManager()).thenReturn(credentials);
            when(user.getRequiredActionsStream()).thenAnswer(ignored -> Stream.empty());
            totpAction.setAlias("CONFIGURE_TOTP");
            totpAction.setProviderId("CONFIGURE_TOTP");
            totpAction.setEnabled(true);
            when(realm.getRequiredActionProviderByAlias("CONFIGURE_TOTP")).thenReturn(totpAction);
        }

        private void pendingTotpEnrollment() {
            when(user.getRequiredActionsStream()).thenAnswer(ignored ->
                    Stream.of("CONFIGURE_TOTP", "CONFIGURE_RECOVERY_AUTHN_CODES"));
        }
    }
}
