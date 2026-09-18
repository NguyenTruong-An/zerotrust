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
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

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
        );
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
        ));
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
                new TrustedDeviceRegistrationRequest("user-1", "generated-device-id")
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
                new TrustedDeviceRegistrationRequest("user-1", "revoked-device-id")
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
            when(context.getRealm()).thenReturn(realm);
            when(realm.getAuthenticatorConfigById(CONFIG_ID)).thenReturn(evaluatorConfig);
            when(configResolver.resolve(evaluatorConfig)).thenReturn(config);
            when(clientFactory.create(config)).thenReturn(client);
            when(context.getUser()).thenReturn(user);
            when(user.getId()).thenReturn("user-1");
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
}
