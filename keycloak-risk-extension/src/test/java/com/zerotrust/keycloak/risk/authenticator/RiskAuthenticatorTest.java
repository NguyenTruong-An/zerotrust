package com.zerotrust.keycloak.risk.authenticator;

import com.zerotrust.keycloak.risk.client.RiskScoringClient;
import com.zerotrust.keycloak.risk.client.RiskScoringClientException;
import com.zerotrust.keycloak.risk.client.RiskScoringClientFactory;
import com.zerotrust.keycloak.risk.config.RiskAuthenticatorConfig;
import com.zerotrust.keycloak.risk.config.RiskAuthenticatorConfigResolver;
import com.zerotrust.keycloak.risk.config.RiskScoringClientConfig;
import com.zerotrust.keycloak.risk.context.LoginContextExtractor;
import com.zerotrust.keycloak.risk.dto.RiskEvaluationRequest;
import com.zerotrust.keycloak.risk.dto.RiskEvaluationResponse;
import com.zerotrust.keycloak.risk.policy.RiskDecisionHandler;
import com.zerotrust.keycloak.risk.policy.RiskFailureMode;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;

import java.net.URI;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RiskAuthenticatorTest {

    @Test
    void evaluatesExtractedContextAndHandlesDecision() {
        Fixture fixture = new Fixture();
        RiskEvaluationResponse evaluation = mock(RiskEvaluationResponse.class);
        when(fixture.client.evaluate(fixture.request)).thenReturn(evaluation);

        fixture.authenticator.authenticate(fixture.context);

        verify(fixture.clientFactory).create(fixture.config.clientConfig());
        verify(fixture.client).evaluate(fixture.request);
        verify(fixture.decisionHandler).handle(fixture.context, evaluation);
    }

    @Test
    void appliesConfiguredStepUpWhenRiskServiceFails() {
        Fixture fixture = new Fixture(RiskFailureMode.STEP_UP_MFA);
        RiskScoringClientException clientException = mock(RiskScoringClientException.class);
        when(clientException.failureType())
                .thenReturn(RiskScoringClientException.FailureType.TIMEOUT);
        when(clientException.statusCode()).thenReturn(-1);
        when(fixture.client.evaluate(fixture.request)).thenThrow(clientException);

        fixture.authenticator.authenticate(fixture.context);

        verify(fixture.decisionHandler).handleUnavailable(
                fixture.context,
                RiskFailureMode.STEP_UP_MFA,
                "TIMEOUT"
        );
    }

    private static final class Fixture {
        private final AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        private final AuthenticatorConfigModel authenticatorConfig = mock(AuthenticatorConfigModel.class);
        private final LoginContextExtractor contextExtractor = mock(LoginContextExtractor.class);
        private final RiskAuthenticatorConfigResolver configResolver = mock(
                RiskAuthenticatorConfigResolver.class
        );
        private final RiskScoringClientFactory clientFactory = mock(RiskScoringClientFactory.class);
        private final RiskScoringClient client = mock(RiskScoringClient.class);
        private final RiskDecisionHandler decisionHandler = mock(RiskDecisionHandler.class);
        private final RiskEvaluationRequest request = new RiskEvaluationRequest(
                "user-1",
                "root-session:tab-1",
                "zerotrust-spa",
                "203.0.113.10",
                "Mozilla/5.0",
                "device-123"
        );
        private final RiskAuthenticatorConfig config;
        private final RiskAuthenticator authenticator;

        private Fixture() {
            this(RiskFailureMode.DENY);
        }

        private Fixture(RiskFailureMode failureMode) {
            config = new RiskAuthenticatorConfig(
                    RiskScoringClientConfig.defaults(URI.create("http://localhost:8081")),
                    failureMode
            );
            when(context.getAuthenticatorConfig()).thenReturn(authenticatorConfig);
            when(configResolver.resolve(authenticatorConfig)).thenReturn(config);
            when(contextExtractor.extract(context)).thenReturn(request);
            when(clientFactory.create(config.clientConfig())).thenReturn(client);
            authenticator = new RiskAuthenticator(
                    contextExtractor,
                    configResolver,
                    clientFactory,
                    decisionHandler
            );
        }
    }
}
