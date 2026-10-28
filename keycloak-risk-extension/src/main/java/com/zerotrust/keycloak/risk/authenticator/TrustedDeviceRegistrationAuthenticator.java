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
import com.zerotrust.keycloak.risk.trace.RiskEvaluationTrace;
import static com.zerotrust.keycloak.risk.trace.RiskEvaluationTrace.Stage.DEVICE_REGISTRATION;
import static com.zerotrust.keycloak.risk.trace.RiskEvaluationTrace.Outcome.*;
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
        RiskEvaluationTrace.DEFAULT.registrationReached(context);
        if (!isEligible(authenticationSession)) {
            RiskEvaluationTrace.DEFAULT.observe(context, DEVICE_REGISTRATION, NOT_ELIGIBLE);
            context.success();
            return;
        }

        String evaluatorConfigId = authenticationSession.getAuthNote(
                RiskAuthenticationNotes.EVALUATOR_CONFIG_ID
        );
        String generation = authenticationSession.getAuthNote(RiskAuthenticationNotes.TRUST_GENERATION);
        boolean rotate = Boolean.parseBoolean(authenticationSession.getAuthNote(RiskAuthenticationNotes.ROTATE_DEVICE));
        clearRegistrationNotes(authenticationSession);

        // Required actions run after the browser flow: enrollment has not yet proved MFA.
        if (requireUser(context).getRequiredActionsStream().anyMatch("CONFIGURE_TOTP"::equals)) {
            RiskEvaluationTrace.DEFAULT.observe(context, DEVICE_REGISTRATION, ENROLLMENT_PENDING);
            if (rotate) expireRejectedCookie(context);
            context.success();
            return;
        }

        try {
            AuthenticatorConfigModel evaluatorConfig = findEvaluatorConfig(
                    context,
                    evaluatorConfigId
            );
            RiskAuthenticatorConfig config = configResolver.resolve(evaluatorConfig);
            if (generation == null) throw new IllegalStateException("Trust generation is unavailable");
            String deviceId = rotate ? null : deviceIdResolver.resolve(context);
            if (deviceId == null) {
                deviceId = deviceIdGenerator.generate();
            }

            clientFactory.create(config).register(new TrustedDeviceRegistrationRequest(
                    requireUser(context).getId(),
                    deviceId,
                    Long.parseLong(generation)
            ));
            RiskEvaluationTrace.DEFAULT.observe(context, DEVICE_REGISTRATION, REGISTERED_204);
            cookieWriter.issue(context, deviceId);
            RiskEvaluationTrace.DEFAULT.observe(context, DEVICE_REGISTRATION, COOKIE_ISSUED);
        } catch (RiskScoringClientException exception) {
            RiskEvaluationTrace.DEFAULT.observe(context, DEVICE_REGISTRATION,
                    exception.statusCode() == 409 ? REGISTRATION_REJECTED : REGISTRATION_UNAVAILABLE);
            LOGGER.warnf(
                    "Trusted-device registration failed: type=%s, status=%d",
                    exception.failureType(),
                    exception.statusCode()
            );
            if (exception.statusCode() == 409) {
                expireRejectedCookie(context);
            }
        } catch (RuntimeException exception) {
            RiskEvaluationTrace.DEFAULT.observe(context, DEVICE_REGISTRATION, REGISTRATION_ERROR);
            LOGGER.error("Trusted-device registration could not be completed; details suppressed");
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
        session.removeAuthNote(RiskAuthenticationNotes.TRUST_GENERATION);
        session.removeAuthNote(RiskAuthenticationNotes.ROTATE_DEVICE);
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
            LOGGER.warn("Could not expire a rejected trusted-device cookie; details suppressed");
        }
    }
}
