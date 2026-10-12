package com.zerotrust.keycloak.risk.authenticator;

import com.zerotrust.keycloak.risk.policy.RiskAuthenticationNotes;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.models.UserModel;

public final class RiskStepUpCondition implements ConditionalAuthenticator {

    public static final RiskStepUpCondition INSTANCE = new RiskStepUpCondition();
    private static final String CONFIGURE_TOTP = UserModel.RequiredAction.CONFIGURE_TOTP.name();

    private RiskStepUpCondition() {
    }

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        boolean stepUpRequired = Boolean.parseBoolean(
                context.getAuthenticationSession().getAuthNote(
                        RiskAuthenticationNotes.STEP_UP_REQUIRED
                )
        );
        if (!stepUpRequired) {
            return false;
        }

        UserModel user = context.getUser();
        RealmModel realm = context.getRealm();
        if (user == null || realm == null
                || user.getRequiredActionsStream().noneMatch(CONFIGURE_TOTP::equals)) {
            return true;
        }
        RequiredActionProviderModel enrollment = realm.getRequiredActionProviderByAlias(CONFIGURE_TOTP);
        if (enrollment == null || !enrollment.isEnabled()
                || !CONFIGURE_TOTP.equals(enrollment.getProviderId())) {
            return true;
        }

        // After reset neither ALTERNATIVE MFA method is configured, so Keycloak cannot
        // finish this subflow. Mandatory TOTP enrollment runs after the browser flow;
        // device registration also skips users with this pending required action.
        return user.credentialManager().isConfiguredFor("otp")
                || user.credentialManager().isConfiguredFor("recovery-authn-codes");
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Conditional authenticators do not issue an action challenge.
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public void setRequiredActions(
            KeycloakSession session,
            RealmModel realm,
            UserModel user
    ) {
        // Enrollment must already be a mandatory user action before deferring MFA.
    }

    @Override
    public void close() {
        // Stateless singleton.
    }
}
