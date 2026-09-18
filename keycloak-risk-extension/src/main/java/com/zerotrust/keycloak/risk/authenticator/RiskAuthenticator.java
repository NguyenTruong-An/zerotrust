package com.zerotrust.keycloak.risk.authenticator;

import com.zerotrust.keycloak.risk.client.RiskScoringClientException;
import com.zerotrust.keycloak.risk.client.RiskScoringClientFactory;
import com.zerotrust.keycloak.risk.config.RiskAuthenticatorConfig;
import com.zerotrust.keycloak.risk.config.RiskAuthenticatorConfigResolver;
import com.zerotrust.keycloak.risk.context.LoginContextExtractor;
import com.zerotrust.keycloak.risk.dto.RiskEvaluationRequest;
import com.zerotrust.keycloak.risk.dto.RiskEvaluationResponse;
import com.zerotrust.keycloak.risk.dto.RiskDecision;
import com.zerotrust.keycloak.risk.policy.RiskAuthenticationNotes;
import com.zerotrust.keycloak.risk.policy.RiskDecisionHandler;
import com.zerotrust.keycloak.risk.policy.RiskFailureMode;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.Objects;

public final class RiskAuthenticator implements Authenticator {

    private static final Logger LOGGER = Logger.getLogger(RiskAuthenticator.class);

    private final LoginContextExtractor contextExtractor;
    private final RiskAuthenticatorConfigResolver configResolver;
    private final RiskScoringClientFactory clientFactory;
    private final RiskDecisionHandler decisionHandler;

    public RiskAuthenticator(
            LoginContextExtractor contextExtractor,
            RiskAuthenticatorConfigResolver configResolver,
            RiskScoringClientFactory clientFactory,
            RiskDecisionHandler decisionHandler
    ) {
        this.contextExtractor = Objects.requireNonNull(
                contextExtractor,
                "contextExtractor must not be null"
        );
        this.configResolver = Objects.requireNonNull(
                configResolver,
                "configResolver must not be null"
        );
        this.clientFactory = Objects.requireNonNull(clientFactory, "clientFactory must not be null");
        this.decisionHandler = Objects.requireNonNull(
                decisionHandler,
                "decisionHandler must not be null"
        );
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        RiskFailureMode failureMode = RiskFailureMode.DENY;
        try {
            RiskAuthenticatorConfig config = configResolver.resolve(context.getAuthenticatorConfig());
            failureMode = config.failureMode();

            RiskEvaluationRequest request = contextExtractor.extract(context);
            RiskEvaluationResponse evaluation = clientFactory
                    .create(config)
                    .evaluate(request);
            decisionHandler.handle(context, evaluation);
            rememberEvaluatorConfig(context, evaluation);
        } catch (RiskScoringClientException exception) {
            LOGGER.warnf(
                    "Risk Scoring Service call failed: type=%s, status=%d",
                    exception.failureType(),
                    exception.statusCode()
            );
            decisionHandler.handleUnavailable(
                    context,
                    failureMode,
                    exception.failureType().name()
            );
        } catch (RuntimeException exception) {
            LOGGER.error("Risk authentication failed before a valid decision was produced", exception);
            decisionHandler.handleUnavailable(
                    context,
                    RiskFailureMode.DENY,
                    "INTERNAL_ERROR"
            );
        }
    }

    private static void rememberEvaluatorConfig(
            AuthenticationFlowContext context,
            RiskEvaluationResponse evaluation
    ) {
        if (evaluation.decision() != RiskDecision.STEP_UP_MFA
                || context.getAuthenticatorConfig() == null
                || context.getAuthenticatorConfig().getId() == null
                || context.getAuthenticatorConfig().getId().isBlank()) {
            return;
        }
        context.getAuthenticationSession().setAuthNote(
                RiskAuthenticationNotes.EVALUATOR_CONFIG_ID,
                context.getAuthenticatorConfig().getId()
        );
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        decisionHandler.handleUnavailable(
                context,
                RiskFailureMode.DENY,
                "UNEXPECTED_ACTION"
        );
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(
            KeycloakSession session,
            RealmModel realm,
            UserModel user
    ) {
        return true;
    }

    @Override
    public void setRequiredActions(
            KeycloakSession session,
            RealmModel realm,
            UserModel user
    ) {
        // The OTP execution in the conditional subflow owns MFA enrollment.
    }

    @Override
    public void close() {
        // The Keycloak-managed HttpClientProvider owns the HTTP client lifecycle.
    }
}
