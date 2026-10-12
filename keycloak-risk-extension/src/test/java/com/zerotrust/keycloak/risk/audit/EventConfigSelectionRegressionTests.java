package com.zerotrust.keycloak.risk.audit;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;

import java.util.List;
import java.util.stream.Stream;

import static com.zerotrust.keycloak.risk.audit.SpiAuditFixture.*;
import static org.junit.jupiter.api.Assertions.*;

class EventConfigSelectionRegressionTests {

    @TestFactory
    Stream<DynamicTest> activeMonitoringSurvivesDisabledConfigurations() {
        return Stream.of("disabled-before", "disabled-after", "nested-disabled", "same-client-disabled")
                .flatMap(placement -> Stream.of(EventType.LOGIN, EventType.LOGIN_ERROR)
                        .map(type -> DynamicTest.dynamicTest(placement + " " + type, () -> {
                            try (var fixture = new SpiAuditFixture()) {
                                var disabled = fixture.addConfig("qa-disabled",
                                        placement.equals("same-client-disabled") ? "qa-browser" : "qa-unmonitored");
                                // If selected, this stale config would send to a different path and fail.
                                disabled.getConfig().put("riskServiceBaseUrl", fixture.base() + "/disabled");
                                disabled.getConfig().put("tokenEndpointUrl", fixture.base() + "/disabled-token");
                                if (placement.equals("nested-disabled")) {
                                    fixture.executions.put("qa-browser-flow", List.of(subflow("parent", Requirement.REQUIRED)));
                                    fixture.executions.put("parent", List.of(
                                            subflow("disabled-child", Requirement.DISABLED),
                                            evaluator("qa-risk", 20, Requirement.REQUIRED)));
                                    fixture.executions.put("disabled-child", List.of(subflow("grandchild", Requirement.REQUIRED)));
                                    fixture.executions.put("grandchild", List.of(evaluator("qa-disabled", 1, Requirement.REQUIRED)));
                                } else {
                                    fixture.executions.put("qa-browser-flow", List.of(
                                            evaluator("qa-disabled", placement.equals("disabled-after") ? 30 : 10, Requirement.DISABLED),
                                            evaluator("qa-risk", 20, Requirement.REQUIRED)));
                                }

                                fixture.evaluator().authenticate(fixture.context);
                                assertEquals(1, fixture.at(EVALUATE).size());
                                int successes = fixture.successes.get();
                                fixture.listener().onEvent(EventDeliverySpiAuditTests.event(type));

                                assertEquals(1, fixture.at(type == EventType.LOGIN ? SUCCESS : FAILURE).size());
                                assertEquals(0, fixture.at(type == EventType.LOGIN ? FAILURE : SUCCESS).size());
                                assertTrue(fixture.calls.stream().noneMatch(call -> call.path().startsWith("/disabled")));
                                assertEquals(successes, fixture.successes.get());
                                assertEquals(0, fixture.denials.get());
                                assertTrue(fixture.emitted.isEmpty());
                            }
                        })));
    }

    @TestFactory
    Stream<DynamicTest> noActiveEvaluatorDoesNotDeliverOrChangeAuthentication() {
        return Stream.of(false, true).flatMap(disabledParent -> Stream.of(EventType.LOGIN, EventType.LOGIN_ERROR)
                .map(type -> DynamicTest.dynamicTest("disabled-parent=" + disabledParent + " " + type, () -> {
                    try (var fixture = new SpiAuditFixture()) {
                        fixture.executions.put("qa-browser-flow", disabledParent
                                ? List.of(subflow("disabled-parent", Requirement.DISABLED))
                                : List.of(evaluator("qa-risk", 10, Requirement.DISABLED)));
                        fixture.executions.put("disabled-parent", List.of(evaluator("qa-risk", 10, Requirement.REQUIRED)));

                        assertDoesNotThrow(() -> fixture.listener().onEvent(EventDeliverySpiAuditTests.event(type)));
                        assertTrue(fixture.calls.isEmpty());
                        assertEquals(0, fixture.successes.get());
                        assertEquals(0, fixture.denials.get());
                        assertTrue(fixture.emitted.isEmpty());
                    }
                })));
    }

    private static AuthenticationExecutionModel subflow(String flowId, Requirement requirement) {
        AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
        execution.setAuthenticatorFlow(true);
        execution.setFlowId(flowId);
        execution.setPriority(5);
        execution.setRequirement(requirement);
        return execution;
    }
}
