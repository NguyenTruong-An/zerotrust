package com.zerotrust.keycloak.risk.authenticator;

import com.zerotrust.keycloak.risk.policy.RiskAuthenticationNotes;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public final class RiskStepUpCondition implements ConditionalAuthenticator {

    public static final RiskStepUpCondition INSTANCE = new RiskStepUpCondition();

    private RiskStepUpCondition() {
    }

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        return Boolean.parseBoolean(
                context.getAuthenticationSession().getAuthNote(
                        RiskAuthenticationNotes.STEP_UP_REQUIRED
                )
        );
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
        // The OTP execution inside the conditional subflow handles user setup.
    }

    @Override
    public void close() {
        // Stateless singleton.
    }
}
