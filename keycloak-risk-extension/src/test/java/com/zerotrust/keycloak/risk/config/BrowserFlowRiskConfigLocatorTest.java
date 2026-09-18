package com.zerotrust.keycloak.risk.config;

import com.zerotrust.keycloak.risk.authenticator.RiskAuthenticatorFactory;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class BrowserFlowRiskConfigLocatorTest {

    private final BrowserFlowRiskConfigLocator locator = new BrowserFlowRiskConfigLocator();

    @Test
    void findsEvaluatorConfigInsideNestedBrowserSubflow() {
        RealmModel realm = mock(RealmModel.class);
        AuthenticationFlowModel browserFlow = new AuthenticationFlowModel();
        browserFlow.setId("browser-flow");
        when(realm.getBrowserFlow()).thenReturn(browserFlow);

        AuthenticationExecutionModel subflow = new AuthenticationExecutionModel();
        subflow.setAuthenticatorFlow(true);
        subflow.setFlowId("nested-flow");
        subflow.setPriority(10);
        AuthenticationExecutionModel evaluator = new AuthenticationExecutionModel();
        evaluator.setAuthenticator(RiskAuthenticatorFactory.PROVIDER_ID);
        evaluator.setAuthenticatorConfig("risk-config");
        evaluator.setPriority(20);
        AuthenticatorConfigModel expected = new AuthenticatorConfigModel();
        expected.setId("risk-config");

        when(realm.getAuthenticationExecutionsStream("browser-flow"))
                .thenReturn(Stream.of(subflow));
        when(realm.getAuthenticationExecutionsStream("nested-flow"))
                .thenReturn(Stream.of(evaluator));
        when(realm.getAuthenticatorConfigById("risk-config")).thenReturn(expected);

        assertSame(expected, locator.locate(realm));
    }

    @Test
    void rejectsBrowserFlowWithoutRiskEvaluatorConfig() {
        RealmModel realm = mock(RealmModel.class);
        AuthenticationFlowModel browserFlow = new AuthenticationFlowModel();
        browserFlow.setId("browser-flow");
        when(realm.getBrowserFlow()).thenReturn(browserFlow);
        when(realm.getAuthenticationExecutionsStream("browser-flow"))
                .thenReturn(Stream.empty());

        assertThrows(
                RiskAuthenticatorConfigurationException.class,
                () -> locator.locate(realm)
        );
    }
}
