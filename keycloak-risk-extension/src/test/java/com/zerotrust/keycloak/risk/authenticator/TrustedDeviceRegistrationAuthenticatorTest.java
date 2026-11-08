package com.zerotrust.keycloak.risk.authenticator;

import com.zerotrust.keycloak.risk.client.RiskScoringClientException;
import com.zerotrust.keycloak.risk.client.TrustedDeviceClient;
import com.zerotrust.keycloak.risk.client.TrustedDeviceClientFactory;
import com.zerotrust.keycloak.risk.config.RiskAuthenticatorConfig;
import com.zerotrust.keycloak.risk.config.RiskAuthenticatorConfigResolver;
import com.zerotrust.keycloak.risk.context.DeviceCookieWriter;
import com.zerotrust.keycloak.risk.context.DeviceIdGenerator;
import com.zerotrust.keycloak.risk.context.DeviceIdResolver;
import com.zerotrust.keycloak.risk.dto.TrustedDeviceRegistrationRequest;
import com.zerotrust.keycloak.risk.policy.RiskAuthenticationNotes;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class TrustedDeviceRegistrationAuthenticatorTest {

    @Test
    void skipsWhenRiskEvaluationDidNotMakeDeviceEligible() {
        Fixture fixture = new Fixture(false);

        fixture.authenticator.authenticate(fixture.context);

        verify(fixture.context).success();
        verifyNoInteractions(fixture.configResolver, fixture.clientFactory, fixture.cookieWriter);
    }

    @Test
    void registersGeneratedIdAndIssuesCookieAfterEligibleMfa() {
        Fixture fixture = new Fixture(true);

        fixture.authenticator.authenticate(fixture.context);

        TrustedDeviceRegistrationRequest expected = new TrustedDeviceRegistrationRequest(
                "user-1",
                "generated-device-id"
        , 0);
        verify(fixture.client).register(expected);
        verify(fixture.cookieWriter).issue(fixture.context, "generated-device-id");
        verify(fixture.authenticationSession).removeAuthNote(
                RiskAuthenticationNotes.TRUST_DEVICE_ELIGIBLE
        );
        verify(fixture.authenticationSession).removeAuthNote(
                RiskAuthenticationNotes.EVALUATOR_CONFIG_ID
        );
        verify(fixture.context).success();
    }

    @Test
    void reusesValidExistingCookieInsteadOfGeneratingAnotherId() {
        Fixture fixture = new Fixture(true);
        when(fixture.deviceIdResolver.resolve(fixture.context)).thenReturn("existing-device-id");

        fixture.authenticator.authenticate(fixture.context);

        verify(fixture.client).register(new TrustedDeviceRegistrationRequest(
                "user-1",
                "existing-device-id"
        , 0));
        verifyNoInteractions(fixture.deviceIdGenerator);
        verify(fixture.cookieWriter).issue(fixture.context, "existing-device-id");
    }

    @Test
    void allowsLoginWithoutCookieWhenRegistrationServiceIsUnavailable() {
        Fixture fixture = new Fixture(true);
        RiskScoringClientException failure = mock(RiskScoringClientException.class);
        when(failure.failureType()).thenReturn(
                RiskScoringClientException.FailureType.CONNECTION_FAILURE
        );
        when(failure.statusCode()).thenReturn(-1);
        org.mockito.Mockito.doThrow(failure).when(fixture.client).register(
                new TrustedDeviceRegistrationRequest("user-1", "generated-device-id", 0)
        );

        fixture.authenticator.authenticate(fixture.context);

        verify(fixture.cookieWriter, never()).issue(fixture.context, "generated-device-id");
        verify(fixture.cookieWriter, never()).expire(fixture.context);
        verify(fixture.context).success();
    }

    @Test
    void expiresRejectedCookieAndAllowsCurrentMfaAuthenticatedLogin() {
        Fixture fixture = new Fixture(true);
        when(fixture.deviceIdResolver.resolve(fixture.context)).thenReturn("revoked-device-id");
        RiskScoringClientException conflict = mock(RiskScoringClientException.class);
        when(conflict.failureType()).thenReturn(RiskScoringClientException.FailureType.HTTP_ERROR);
        when(conflict.statusCode()).thenReturn(409);
        org.mockito.Mockito.doThrow(conflict).when(fixture.client).register(
                new TrustedDeviceRegistrationRequest("user-1", "revoked-device-id", 0)
        );

        fixture.authenticator.authenticate(fixture.context);

        verify(fixture.cookieWriter).expire(fixture.context);
        verify(fixture.cookieWriter, never()).issue(fixture.context, "revoked-device-id");
        verify(fixture.context).success();
    }

    private static final class Fixture {
        private static final String CONFIG_ID = "risk-config-1";

        private final AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        private final AuthenticationSessionModel authenticationSession = mock(
                AuthenticationSessionModel.class
        );
        private final RealmModel realm = mock(RealmModel.class);
        private final UserModel user = mock(UserModel.class);
        private final AuthenticatorConfigModel evaluatorConfig = mock(
                AuthenticatorConfigModel.class
        );
        private final RiskAuthenticatorConfig config = mock(RiskAuthenticatorConfig.class);
        private final DeviceIdResolver deviceIdResolver = mock(DeviceIdResolver.class);
        private final DeviceIdGenerator deviceIdGenerator = mock(DeviceIdGenerator.class);
        private final DeviceCookieWriter cookieWriter = mock(DeviceCookieWriter.class);
        private final RiskAuthenticatorConfigResolver configResolver = mock(
                RiskAuthenticatorConfigResolver.class
        );
        private final TrustedDeviceClientFactory clientFactory = mock(
                TrustedDeviceClientFactory.class
        );
        private final TrustedDeviceClient client = mock(TrustedDeviceClient.class);
        private final TrustedDeviceRegistrationAuthenticator authenticator;

        private Fixture(boolean eligible) {
            when(context.getAuthenticationSession()).thenReturn(authenticationSession);
            when(authenticationSession.getAuthNote(RiskAuthenticationNotes.TRUST_DEVICE_ELIGIBLE))
                    .thenReturn(Boolean.toString(eligible));
            when(authenticationSession.getAuthNote(RiskAuthenticationNotes.EVALUATOR_CONFIG_ID))
                    .thenReturn(CONFIG_ID);
            when(authenticationSession.getAuthNote(RiskAuthenticationNotes.TRUST_GENERATION)).thenReturn("0");
            when(context.getRealm()).thenReturn(realm);
            when(realm.getAuthenticatorConfigById(CONFIG_ID)).thenReturn(evaluatorConfig);
            when(configResolver.resolve(evaluatorConfig)).thenReturn(config);
            when(clientFactory.create(config)).thenReturn(client);
            when(context.getUser()).thenReturn(user);
            when(user.getId()).thenReturn("user-1");
            when(authenticationSession.getAuthNote(RiskAuthenticationNotes.EVALUATED_SUBJECT)).thenReturn("user-1");
            when(authenticationSession.getAuthNote(RiskAuthenticationNotes.EVALUATED_SESSION)).thenReturn("root-session:tab-1");
            var root = mock(org.keycloak.sessions.RootAuthenticationSessionModel.class);
            when(authenticationSession.getParentSession()).thenReturn(root);
            when(root.getId()).thenReturn("root-session");
            when(authenticationSession.getTabId()).thenReturn("tab-1");
            when(authenticationSession.getExecutionStatus()).thenReturn(java.util.Map.of("mfa-execution", AuthenticationSessionModel.ExecutionStatus.SUCCESS));
            var otp = new org.keycloak.models.AuthenticationExecutionModel();
            otp.setAuthenticator("auth-otp-form");
            when(realm.getAuthenticationExecutionById("mfa-execution")).thenReturn(otp);
            when(deviceIdGenerator.generate()).thenReturn("generated-device-id");

            authenticator = new TrustedDeviceRegistrationAuthenticator(
                    deviceIdResolver,
                    deviceIdGenerator,
                    cookieWriter,
                    configResolver,
                    clientFactory
            );
        }
    }

    @Test
    void rotatesResetOrExpiredCookieAndSendsCurrentGeneration() {
        Fixture fixture = new Fixture(true);
        when(fixture.authenticationSession.getAuthNote(RiskAuthenticationNotes.ROTATE_DEVICE)).thenReturn("true");
        when(fixture.authenticationSession.getAuthNote(RiskAuthenticationNotes.TRUST_GENERATION)).thenReturn("7");
        fixture.authenticator.authenticate(fixture.context);
        verifyNoInteractions(fixture.deviceIdResolver);
        verify(fixture.client).register(new TrustedDeviceRegistrationRequest("user-1", "generated-device-id", 7));
        verify(fixture.cookieWriter).issue(fixture.context, "generated-device-id");
    }

    @Test
    void doesNotTrustBeforeRequiredMfaEnrollmentCompletes() {
        Fixture fixture = new Fixture(true);
        when(fixture.user.getRequiredActionsStream()).thenAnswer(ignored -> java.util.stream.Stream.of("CONFIGURE_TOTP"));
        when(fixture.user.credentialManager()).thenReturn(mock(SubjectCredentialManager.class));
        RequiredActionProviderModel enrollment = new RequiredActionProviderModel();
        enrollment.setAlias("CONFIGURE_TOTP");
        enrollment.setProviderId("CONFIGURE_TOTP");
        enrollment.setEnabled(true);
        when(fixture.realm.getRequiredActionProviderByAlias("CONFIGURE_TOTP")).thenReturn(enrollment);
        when(fixture.authenticationSession.getAuthNote(RiskAuthenticationNotes.STEP_UP_REQUIRED)).thenReturn("true");
        when(fixture.authenticationSession.getAuthNote(RiskAuthenticationNotes.ROTATE_DEVICE)).thenReturn("true");

        assertFalse(RiskStepUpCondition.INSTANCE.matchCondition(fixture.context));
        fixture.authenticator.authenticate(fixture.context);

        verifyNoInteractions(fixture.client);
        verify(fixture.cookieWriter).expire(fixture.context);
        verify(fixture.cookieWriter, never()).issue(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.anyString());
        verify(fixture.context).success();
    }

    @Test
    void missingGenerationNeverRegistersADevice() {
        Fixture fixture = new Fixture(true);
        when(fixture.authenticationSession.getAuthNote(RiskAuthenticationNotes.TRUST_GENERATION)).thenReturn(null);
        fixture.authenticator.authenticate(fixture.context);
        verifyNoInteractions(fixture.client, fixture.cookieWriter);
        verify(fixture.context).success();
    }

    @Test
    void eligibilityWithoutSuccessfulOtpOrRecoveryCannotCreateTrust() {
        Fixture fixture = new Fixture(true);
        when(fixture.authenticationSession.getExecutionStatus()).thenReturn(java.util.Map.of());
        fixture.authenticator.authenticate(fixture.context);
        verifyNoInteractions(fixture.client, fixture.cookieWriter);
        verify(fixture.context).failure(org.keycloak.authentication.AuthenticationFlowError.ACCESS_DENIED);
        verify(fixture.context, never()).success();
    }

    @Test
    void eligibilityFromAnotherAccountCannotBeUsedByTheCurrentUser() {
        Fixture fixture = new Fixture(true);
        when(fixture.authenticationSession.getAuthNote("zerotrust.risk.evaluated-subject")).thenReturn("previous-user");
        fixture.authenticator.authenticate(fixture.context);
        verifyNoInteractions(fixture.client, fixture.cookieWriter);
        verify(fixture.context).failure(org.keycloak.authentication.AuthenticationFlowError.ACCESS_DENIED);
        verify(fixture.context, never()).success();
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.EnumSource(value = AuthenticationSessionModel.ExecutionStatus.class,
            mode = org.junit.jupiter.params.provider.EnumSource.Mode.EXCLUDE, names = "SUCCESS")
    void challengedAttemptedOrFailedMfaIsNotProof(AuthenticationSessionModel.ExecutionStatus status) {
        Fixture fixture = new Fixture(true);
        when(fixture.authenticationSession.getExecutionStatus()).thenReturn(java.util.Map.of("mfa-execution", status));
        fixture.authenticator.authenticate(fixture.context);
        verifyNoInteractions(fixture.client, fixture.cookieWriter);
        verify(fixture.context).failure(org.keycloak.authentication.AuthenticationFlowError.ACCESS_DENIED);
    }

    @Test
    void completedRecoveryIsValidMfaProof() {
        Fixture fixture = new Fixture(true);
        var recovery = new org.keycloak.models.AuthenticationExecutionModel();
        recovery.setAuthenticator("auth-recovery-authn-code-form");
        when(fixture.realm.getAuthenticationExecutionById("mfa-execution")).thenReturn(recovery);
        fixture.authenticator.authenticate(fixture.context);
        verify(fixture.client).register(new TrustedDeviceRegistrationRequest("user-1", "generated-device-id", 0));
        verify(fixture.cookieWriter).issue(fixture.context, "generated-device-id");
    }

    @Test
    void completedMfaInAnotherAuthenticationTabCannotReuseEligibility() {
        Fixture fixture = new Fixture(true);
        when(fixture.authenticationSession.getTabId()).thenReturn("new-tab");
        fixture.authenticator.authenticate(fixture.context);
        verifyNoInteractions(fixture.client, fixture.cookieWriter);
        verify(fixture.context).failure(org.keycloak.authentication.AuthenticationFlowError.ACCESS_DENIED);
    }

    @Test
    void successfulRegistrationConsumesEligibilityBeforeAnotherInvocation() {
        Fixture fixture = new Fixture(true);
        java.util.Map<String, String> notes = new java.util.HashMap<>(java.util.Map.of(
                RiskAuthenticationNotes.TRUST_DEVICE_ELIGIBLE, "true", RiskAuthenticationNotes.TRUST_GENERATION, "0",
                RiskAuthenticationNotes.EVALUATOR_CONFIG_ID, "risk-config-1",
                RiskAuthenticationNotes.EVALUATED_SUBJECT, "user-1",
                RiskAuthenticationNotes.EVALUATED_SESSION, "root-session:tab-1"));
        when(fixture.authenticationSession.getAuthNote(org.mockito.ArgumentMatchers.anyString()))
                .thenAnswer(call -> notes.get(call.getArgument(0)));
        org.mockito.Mockito.doAnswer(call -> notes.remove(call.getArgument(0)))
                .when(fixture.authenticationSession).removeAuthNote(org.mockito.ArgumentMatchers.anyString());
        fixture.authenticator.authenticate(fixture.context);
        fixture.authenticator.authenticate(fixture.context);
        verify(fixture.client, org.mockito.Mockito.times(1)).register(org.mockito.ArgumentMatchers.any());
        org.junit.jupiter.api.Assertions.assertFalse(notes.containsKey(RiskAuthenticationNotes.EVALUATED_SUBJECT));
        org.junit.jupiter.api.Assertions.assertFalse(notes.containsKey(RiskAuthenticationNotes.TRUST_DEVICE_ELIGIBLE));
    }
}
