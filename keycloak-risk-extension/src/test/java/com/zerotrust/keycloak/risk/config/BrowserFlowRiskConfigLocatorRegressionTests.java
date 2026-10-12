package com.zerotrust.keycloak.risk.config;

import com.zerotrust.keycloak.risk.authenticator.RiskAuthenticatorFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BrowserFlowRiskConfigLocatorRegressionTests {

    private final BrowserFlowRiskConfigLocator locator = new BrowserFlowRiskConfigLocator();
    private final RealmModel realm = mock(RealmModel.class);
    private final Map<String, List<AuthenticationExecutionModel>> flows = new HashMap<>();
    private final Map<String, AuthenticatorConfigModel> configs = new HashMap<>();
    private AuthenticatorConfigModel activeConfig;

    @BeforeEach
    void setUp() {
        AuthenticationFlowModel browser = new AuthenticationFlowModel();
        browser.setId("browser");
        when(realm.getBrowserFlow()).thenReturn(browser);
        when(realm.getAuthenticationExecutionsStream(anyString()))
                .thenAnswer(call -> flows.getOrDefault(call.getArgument(0), List.of()).stream());
        when(realm.getAuthenticatorConfigById(anyString()))
                .thenAnswer(call -> configs.get(call.getArgument(0)));
        activeConfig = config("active");
        config("disabled");
    }

    @ParameterizedTest
    @CsvSource({"20,10", "10,20", "10,10", "10,-10"})
    void disabledEvaluatorCannotWinAtAnyPriority(int activePriority, int disabledPriority) {
        flows.put("browser", List.of(
                evaluator("disabled", disabledPriority, Requirement.DISABLED),
                evaluator("active", activePriority, Requirement.REQUIRED)
        ));

        assertSame(activeConfig, locator.locate(realm));
        verify(realm, never()).getAuthenticatorConfigById("disabled");
    }

    @Test
    void disabledSubflowInsideEnabledParentIsNotTraversed() {
        flows.put("browser", List.of(subflow("parent", 5, Requirement.REQUIRED)));
        flows.put("parent", List.of(
                subflow("disabled-child", 1, Requirement.DISABLED),
                evaluator("active", 20, Requirement.REQUIRED)
        ));
        flows.put("disabled-child", List.of(subflow("grandchild", 1, Requirement.REQUIRED)));
        flows.put("grandchild", List.of(evaluator("disabled", 1, Requirement.REQUIRED)));

        assertSame(activeConfig, locator.locate(realm));
        verify(realm, never()).getAuthenticationExecutionsStream("disabled-child");
        verify(realm, never()).getAuthenticationExecutionsStream("grandchild");
        verify(realm, never()).getAuthenticatorConfigById("disabled");
    }

    @Test
    void skippedDisabledParentDoesNotMarkSharedFlowVisited() {
        flows.put("browser", List.of(
                subflow("shared", 1, Requirement.DISABLED),
                subflow("shared", 20, Requirement.REQUIRED)
        ));
        flows.put("shared", List.of(evaluator("active", 10, Requirement.REQUIRED)));

        assertSame(activeConfig, locator.locate(realm));
        verify(realm, times(1)).getAuthenticationExecutionsStream("shared");
    }

    @ParameterizedTest
    @EnumSource(value = Requirement.class, names = {"REQUIRED", "ALTERNATIVE", "CONDITIONAL"})
    void preservesNestedLookupForNonDisabledSubflows(Requirement parentRequirement) {
        flows.put("browser", List.of(subflow("parent", 10, parentRequirement)));
        flows.put("parent", List.of(subflow("child", 10, Requirement.REQUIRED)));
        flows.put("child", List.of(
                evaluator("disabled", 1, Requirement.DISABLED),
                evaluator("active", 20, Requirement.REQUIRED)
        ));

        // This preserves locator traversal; it does not evaluate engine conditions.
        assertSame(activeConfig, locator.locate(realm));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void rejectsGraphWithOnlyDisabledEvaluatorOrDisabledAncestor(boolean disabledParent) {
        flows.put("browser", disabledParent
                ? List.of(subflow("disabled-parent", 1, Requirement.DISABLED))
                : List.of(evaluator("disabled", 1, Requirement.DISABLED)));
        flows.put("disabled-parent", List.of(evaluator("active", 1, Requirement.REQUIRED)));

        assertThrows(RiskAuthenticatorConfigurationException.class, () -> locator.locate(realm));
        verify(realm, never()).getAuthenticationExecutionsStream("disabled-parent");
        verify(realm, never()).getAuthenticatorConfigById("disabled");
        verify(realm, never()).getAuthenticatorConfigById("active");
    }

    @Test
    void enabledCycleStillAllowsLaterActiveEvaluator() {
        flows.put("browser", List.of(
                subflow("nested", 1, Requirement.REQUIRED),
                evaluator("active", 20, Requirement.REQUIRED)
        ));
        flows.put("nested", List.of(subflow("browser", 1, Requirement.REQUIRED)));

        assertTimeoutPreemptively(Duration.ofSeconds(2),
                () -> assertSame(activeConfig, locator.locate(realm)));
        verify(realm, times(1)).getAuthenticationExecutionsStream("browser");
    }

    @Test
    void enabledCycleWithoutActiveEvaluatorTerminatesWithConfigurationError() {
        flows.put("browser", List.of(subflow("nested", 1, Requirement.REQUIRED)));
        flows.put("nested", List.of(
                subflow("browser", 1, Requirement.REQUIRED),
                evaluator("disabled", 20, Requirement.DISABLED)
        ));

        assertTimeoutPreemptively(Duration.ofSeconds(2),
                () -> assertThrows(RiskAuthenticatorConfigurationException.class,
                        () -> locator.locate(realm)));
        verify(realm, times(1)).getAuthenticationExecutionsStream("browser");
    }

    @Test
    void preservesExistingPrioritySelectionAmongActiveEvaluators() {
        AuthenticatorConfigModel earlier = config("earlier-active");
        flows.put("browser", List.of(
                evaluator("active", 20, Requirement.REQUIRED),
                evaluator("earlier-active", 10, Requirement.REQUIRED)
        ));

        // Characterization of existing priority behavior, not a new multi-evaluator policy.
        assertSame(earlier, locator.locate(realm));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "missing"})
    void preservesFallbackPastUnconfiguredEvaluator(String configId) {
        flows.put("browser", List.of(
                evaluator(configId, 1, Requirement.REQUIRED),
                evaluator("active", 20, Requirement.REQUIRED)
        ));

        assertSame(activeConfig, locator.locate(realm));
    }

    private AuthenticatorConfigModel config(String id) {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setId(id);
        configs.put(id, config);
        return config;
    }

    private static AuthenticationExecutionModel evaluator(String configId, int priority, Requirement requirement) {
        AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
        execution.setAuthenticator(RiskAuthenticatorFactory.PROVIDER_ID);
        execution.setAuthenticatorConfig(configId);
        execution.setPriority(priority);
        execution.setRequirement(requirement);
        return execution;
    }

    private static AuthenticationExecutionModel subflow(String flowId, int priority, Requirement requirement) {
        AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
        execution.setAuthenticatorFlow(true);
        execution.setFlowId(flowId);
        execution.setPriority(priority);
        execution.setRequirement(requirement);
        return execution;
    }
}
