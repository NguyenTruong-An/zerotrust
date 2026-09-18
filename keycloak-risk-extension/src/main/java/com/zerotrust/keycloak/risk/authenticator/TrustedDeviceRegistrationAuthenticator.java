package com.zerotrust.keycloak.risk.authenticator;

import com.zerotrust.keycloak.risk.client.RiskScoringClientException;
import com.zerotrust.keycloak.risk.client.TrustedDeviceClientFactory;
import com.zerotrust.keycloak.risk.config.RiskAuthenticatorConfig;
import com.zerotrust.keycloak.risk.config.RiskAuthenticatorConfigResolver;
import com.zerotrust.keycloak.risk.context.DeviceCookieWriter;
import com.zerotrust.keycloak.risk.context.DeviceIdGenerator;
import com.zerotrust.keycloak.risk.context.DeviceIdResolver;
import com.zerotrust.keycloak.risk.dto.TrustedDeviceRegistrationRequest;
import com.zerotrust.keycloak.risk.policy.RiskAuthenticationNotes;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Objects;

public final class TrustedDeviceRegistrationAuthenticator implements Authenticator {

    private static final Logger LOGGER = Logger.getLogger(
            TrustedDeviceRegistrationAuthenticator.class
    );

    private final DeviceIdResolver deviceIdResolver;
    private final DeviceIdGenerator deviceIdGenerator;
    private final DeviceCookieWriter cookieWriter;
    private final RiskAuthenticatorConfigResolver configResolver;
    private final TrustedDeviceClientFactory clientFactory;

    public TrustedDeviceRegistrationAuthenticator(
            DeviceIdResolver deviceIdResolver,
            DeviceIdGenerator deviceIdGenerator,
            DeviceCookieWriter cookieWriter,
            RiskAuthenticatorConfigResolver configResolver,
            TrustedDeviceClientFactory clientFactory
    ) {
        this.deviceIdResolver = Objects.requireNonNull(
                deviceIdResolver,
                "deviceIdResolver must not be null"
        );
        this.deviceIdGenerator = Objects.requireNonNull(
                deviceIdGenerator,
                "deviceIdGenerator must not be null"
        );
        this.cookieWriter = Objects.requireNonNull(
                cookieWriter,
                "cookieWriter must not be null"
        );
        this.configResolver = Objects.requireNonNull(
                configResolver,
                "configResolver must not be null"
        );
        this.clientFactory = Objects.requireNonNull(
                clientFactory,
                "clientFactory must not be null"
        );
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Objects.requireNonNull(context, "context must not be null");
        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
        if (!isEligible(authenticationSession)) {
            context.success();
            return;
        }

        String evaluatorConfigId = authenticationSession.getAuthNote(
                RiskAuthenticationNotes.EVALUATOR_CONFIG_ID
        );
        clearRegistrationNotes(authenticationSession);

        try {
            AuthenticatorConfigModel evaluatorConfig = findEvaluatorConfig(
                    context,
                    evaluatorConfigId
            );
            RiskAuthenticatorConfig config = configResolver.resolve(evaluatorConfig);
            String deviceId = deviceIdResolver.resolve(context);
            if (deviceId == null) {
                deviceId = deviceIdGenerator.generate();
            }

            clientFactory.create(config).register(new TrustedDeviceRegistrationRequest(
                    requireUser(context).getId(),
                    deviceId
            ));
            cookieWriter.issue(context, deviceId);
        } catch (RiskScoringClientException exception) {
            LOGGER.warnf(
                    "Trusted-device registration failed: type=%s, status=%d",
                    exception.failureType(),
                    exception.statusCode()
            );
            if (exception.statusCode() == 409) {
                expireRejectedCookie(context);
            }
        } catch (RuntimeException exception) {
            LOGGER.error("Trusted-device registration could not be completed", exception);
        }

        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // This execution runs only after the flow's existing OTP step succeeds.
    }

    @Override
    public void close() {
        // The Keycloak-managed HttpClientProvider owns the HTTP client lifecycle.
    }

    private static boolean isEligible(AuthenticationSessionModel session) {
        return session != null && Boolean.parseBoolean(
                session.getAuthNote(RiskAuthenticationNotes.TRUST_DEVICE_ELIGIBLE)
        );
    }

    private static void clearRegistrationNotes(AuthenticationSessionModel session) {
        session.removeAuthNote(RiskAuthenticationNotes.TRUST_DEVICE_ELIGIBLE);
        session.removeAuthNote(RiskAuthenticationNotes.EVALUATOR_CONFIG_ID);
    }

    private static AuthenticatorConfigModel findEvaluatorConfig(
            AuthenticationFlowContext context,
            String evaluatorConfigId
    ) {
        if (evaluatorConfigId == null || evaluatorConfigId.isBlank()) {
            throw new IllegalStateException("Risk evaluator configuration reference is unavailable");
        }
        AuthenticatorConfigModel config = context.getRealm()
                .getAuthenticatorConfigById(evaluatorConfigId);
        if (config == null) {
            throw new IllegalStateException("Risk evaluator configuration no longer exists");
        }
        return config;
    }

    private static UserModel requireUser(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user == null || user.getId() == null || user.getId().isBlank()) {
            throw new IllegalStateException("Authenticated user is unavailable");
        }
        return user;
    }

    private void expireRejectedCookie(AuthenticationFlowContext context) {
        try {
            cookieWriter.expire(context);
        } catch (RuntimeException exception) {
            LOGGER.warn("Could not expire a rejected trusted-device cookie", exception);
        }
    }
}
