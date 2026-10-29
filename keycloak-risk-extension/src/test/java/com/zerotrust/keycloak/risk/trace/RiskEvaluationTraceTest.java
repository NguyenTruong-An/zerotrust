package com.zerotrust.keycloak.risk.trace;

import com.zerotrust.keycloak.risk.dto.*;
import com.zerotrust.keycloak.risk.policy.RiskAuthenticationNotes;
import com.zerotrust.keycloak.risk.policy.RiskDecisionHandler;
import com.zerotrust.keycloak.risk.policy.RiskFailureMode;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import java.math.BigDecimal;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import java.util.function.Consumer;

import static com.zerotrust.keycloak.risk.trace.RiskEvaluationTrace.Stage.*;
import static com.zerotrust.keycloak.risk.trace.RiskEvaluationTrace.Outcome.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class RiskEvaluationTraceTest {
    private static final Instant NOW = Instant.parse("2026-10-28T03:00:00Z");
    private static final UUID EVALUATION = UUID.fromString("5267b997-7d7e-4b0d-9da9-5bc1e98c05e0");

    @ParameterizedTest
    @EnumSource(RiskDecision.class)
    void correlatesEvaluationAndActualEnforcementWithoutChangingDecision(RiskDecision decision) throws Exception {
        Fixture f = new Fixture();
        new RiskDecisionHandler(f.trace).handle(f.context, evaluation(decision, BigDecimal.TEN, RiskDataStatus.COMPLETE));
        assertEquals(2, f.lines.size());
        Map<?, ?> evaluated = row(f, 0);
        Map<?, ?> applied = row(f, 1);
        assertEquals(EVALUATION.toString(), evaluated.get("evaluation_id"));
        assertNotNull(UUID.fromString((String) evaluated.get("correlation_id")));
        assertEquals(evaluated.get("correlation_id"), applied.get("correlation_id"));
        assertEquals(evaluated.get("subject_tag"), applied.get("subject_tag"));
        assertEquals(decision.name(), evaluated.get("decision"));
        assertEquals("zerotrust-spa", evaluated.get("client_id"));
        assertEquals(NOW.toString(), evaluated.get("at"));
        assertEquals(switch (decision) {
            case ALLOW -> "RISK_STEP_PASSED";
            case STEP_UP_MFA -> "STEP_UP_REQUIRED";
            case DENY -> "ACCESS_DENIED";
        }, applied.get("outcome"));
        assertEnforcement(f, decision);
        assertFalse(String.join("", f.lines).contains("MFA_COMPLETED"));
    }

    @Test
    void preservesNullScoreForIncompleteAndPriorityDeny() throws Exception {
        for (RiskDecision decision : List.of(RiskDecision.STEP_UP_MFA, RiskDecision.DENY)) {
            Fixture f = new Fixture();
            new RiskDecisionHandler(f.trace).handle(f.context, evaluation(decision, null,
                    decision == RiskDecision.DENY ? RiskDataStatus.NOT_EVALUATED : RiskDataStatus.INCOMPLETE));
            Map<?, ?> row = row(f, 0);
            assertTrue(row.containsKey("risk_score"));
            assertNull(row.get("risk_score"));
            assertEquals(decision.name(), row.get("decision"));
            assertNotNull(row.get("evaluation_id"));
        }
    }

    @Test
    void failureModeDenyHasNoInventedEvaluationOrHighLevel() throws Exception {
        Fixture f = new Fixture();
        new RiskDecisionHandler(f.trace).handleUnavailable(f.context, RiskFailureMode.DENY, "TIMEOUT");
        Map<?, ?> row = row(f, 0);
        assertEquals("SERVICE_UNAVAILABLE_DENY", row.get("outcome"));
        assertEquals("NO_VALID_RISK_RESPONSE", row.get("evaluation_source"));
        assertEquals("TIMEOUT", row.get("failure_type"));
        assertEquals("DENY", row.get("decision"));
        assertNull(row.get("evaluation_id"));
        assertNull(row.get("risk_level"));
        assertNull(row.get("risk_score"));
        assertEnforcement(f, RiskDecision.DENY);
    }

    @ParameterizedTest
    @EnumSource(RiskDecision.class)
    void brokenLoggingCannotChangeDenyOrMfaOrAllow(RiskDecision decision) {
        Fixture f = new Fixture(line -> { throw new IllegalStateException("sensitive logger failure"); });
        assertDoesNotThrow(() -> new RiskDecisionHandler(f.trace).handle(f.context,
                evaluation(decision, BigDecimal.TEN, RiskDataStatus.COMPLETE)));
        assertEnforcement(f, decision);
    }

    @Test
    void brokenLoggingCannotTurnUnavailableIntoSuccessfulAuthentication() {
        Fixture f = new Fixture(line -> { throw new IllegalStateException("sink down"); });
        assertDoesNotThrow(() -> new RiskDecisionHandler(f.trace)
                .handleUnavailable(f.context, RiskFailureMode.DENY, "TIMEOUT"));
        assertEnforcement(f, RiskDecision.DENY);
    }

    @Test
    void unavailableFallbackStepUpKeepsMfaWithoutTrustEligibility() throws Exception {
        Fixture f = new Fixture();
        new RiskDecisionHandler(f.trace).handleUnavailable(f.context, RiskFailureMode.STEP_UP_MFA, "TIMEOUT");
        assertEquals("SERVICE_UNAVAILABLE_STEP_UP", row(f, 0).get("outcome"));
        assertEquals("true", f.notes.get(RiskAuthenticationNotes.STEP_UP_REQUIRED));
        assertNull(f.notes.get(RiskAuthenticationNotes.TRUST_DEVICE_ELIGIBLE));
        verify(f.context).success();
    }

    @Test
    void tagsAreKeyedRealmScopedAndStableOnlyWithinProcessKey() throws Exception {
        Fixture f = new Fixture();
        f.trace.evaluation(f.context, evaluation(RiskDecision.ALLOW, BigDecimal.ZERO, RiskDataStatus.COMPLETE));
        String original = (String) row(f, 0).get("subject_tag");
        assertTrue(original.matches("[0-9a-f]{32}"));
        f.trace.evaluation(f.context, evaluation(RiskDecision.ALLOW, BigDecimal.ZERO, RiskDataStatus.COMPLETE));
        assertEquals(original, row(f, 1).get("subject_tag"));
        assertNotEquals(row(f, 0).get("correlation_id"), row(f, 1).get("correlation_id"));
        when(f.realm.getId()).thenReturn("different-realm");
        f.trace.evaluation(f.context, evaluation(RiskDecision.ALLOW, BigDecimal.ZERO, RiskDataStatus.COMPLETE));
        assertNotEquals(original, row(f, 2).get("subject_tag"));
        byte[] otherKey = new byte[32]; Arrays.fill(otherKey, (byte) 3);
        new RiskEvaluationTrace(f.lines::add, otherKey, f.clock).evaluation(f.context,
                evaluation(RiskDecision.ALLOW, BigDecimal.ZERO, RiskDataStatus.COMPLETE));
        assertNotEquals(row(f, 2).get("subject_tag"), row(f, 3).get("subject_tag"));
    }

    @Test
    void allowlistExcludesRawContextAndInjectionOrExceptionText() throws Exception {
        Fixture f = new Fixture();
        when(f.client.getClientId()).thenReturn("client\r\nsecret-canary");
        f.trace.evaluation(f.context, evaluation(RiskDecision.ALLOW, BigDecimal.TEN, RiskDataStatus.COMPLETE));
        f.trace.unavailable(f.context, "password=secret-canary", true);
        String text = String.join("", f.lines);
        for (String forbidden : List.of("subject-person-canary", "auth-session-secret-canary",
                "secret-canary", "password=", "203.0.113.77", "Mozilla", "Bearer", "ZT_DEVICE_ID")) {
            assertFalse(text.contains(forbidden), forbidden);
        }
        assertNull(row(f, 0).get("client_id"));
        assertEquals("UNSPECIFIED", row(f, 1).get("failure_type"));
        assertEquals(List.of("TEMPORAL_PROFILE_COLD_START"), row(f, 0).get("reason_codes"));
    }

    @Test
    void challengeAndSelectedGateDoNotClaimOtpCompletion() throws Exception {
        Fixture f = new Fixture();
        f.trace.evaluation(f.context, evaluation(RiskDecision.STEP_UP_MFA, null, RiskDataStatus.INCOMPLETE));
        f.trace.observe(f.context, MFA_GATE, MFA_SUBFLOW_SELECTED);
        f.trace.form(f.auth, MFA_FORM, CHALLENGE_RENDERED);
        f.trace.registrationReached(f.context);
        assertEquals("NOT_OBSERVED", row(f, 3).get("mfa_execution"));
        assertFalse(String.join("", f.lines).contains("OTP_EXECUTION_SUCCESS"));
    }

    @Test
    void actualOtpExecutionAndLoginEventShareEvaluationButNotTokenOrSession() throws Exception {
        Fixture f = new Fixture();
        new RiskDecisionHandler(f.trace).handle(f.context,
                evaluation(RiskDecision.STEP_UP_MFA, BigDecimal.valueOf(45), RiskDataStatus.COMPLETE));
        AuthenticationExecutionModel otp = new AuthenticationExecutionModel();
        otp.setAuthenticator("auth-otp-form");
        when(f.realm.getAuthenticationExecutionById("execution-canary")).thenReturn(otp);
        when(f.auth.getExecutionStatus()).thenReturn(Map.of("execution-canary", AuthenticationSessionModel.ExecutionStatus.CHALLENGED));
        f.trace.registrationReached(f.context);
        assertEquals("NOT_OBSERVED", row(f, 2).get("mfa_execution"));
        when(f.auth.getExecutionStatus()).thenReturn(Map.of("execution-canary", AuthenticationSessionModel.ExecutionStatus.SUCCESS));
        f.trace.registrationReached(f.context);
        assertEquals("OTP_EXECUTION_SUCCESS", row(f, 3).get("mfa_execution"));
        f.trace.authenticationEvent(f.session, f.event(EventType.LOGIN));
        Map<?, ?> login = row(f, 4);
        assertEquals("LOGIN_SUCCESS", login.get("outcome"));
        assertEquals(EVALUATION.toString(), login.get("evaluation_id"));
        assertEquals(row(f, 0).get("correlation_id"), login.get("correlation_id"));
        assertEquals("OTP_EXECUTION_SUCCESS", login.get("mfa_execution"));
        assertFalse(String.join("", f.lines).contains("execution-canary"));
    }

    @Test
    void ssoAndRefreshNeverInventNewEvaluation() throws Exception {
        Fixture f = new Fixture();
        f.notes.put(AuthenticationManager.SSO_AUTH, "true");
        f.trace.authenticationEvent(f.session, f.event(EventType.LOGIN));
        assertEquals("SSO_COOKIE_LOGIN", row(f, 0).get("outcome"));
        assertEquals("NOT_RUN_SSO_COOKIE", row(f, 0).get("risk_execution"));
        assertNull(row(f, 0).get("evaluation_id"));
        new RiskDecisionHandler(f.trace).handle(f.context,
                evaluation(RiskDecision.ALLOW, BigDecimal.ZERO, RiskDataStatus.COMPLETE));
        f.trace.authenticationEvent(f.session, f.event(EventType.REFRESH_TOKEN));
        Map<?, ?> refresh = row(f, 3);
        assertEquals("NOT_RUN_REFRESH", refresh.get("risk_execution"));
        assertNull(refresh.get("evaluation_id"));
        assertNull(refresh.get("correlation_id"));
    }

    @Test
    void missingOrDifferentUserContextIsNotCorrelatedToCurrentLogin() throws Exception {
        Fixture f = new Fixture();
        new RiskDecisionHandler(f.trace).handle(f.context,
                evaluation(RiskDecision.ALLOW, BigDecimal.ZERO, RiskDataStatus.COMPLETE));
        Event event = f.event(EventType.LOGIN);
        event.setUserId("unrelated-user");
        f.trace.authenticationEvent(f.session, event);
        assertEquals("NOT_OBSERVED", row(f, 2).get("risk_execution"));
        assertNull(row(f, 2).get("correlation_id"));
    }

    @Test
    void eventDetailsCarryOnlySafeCorrelationAndClearStaleEvaluationOnFailure() throws Exception {
        Fixture f = new Fixture();
        EventBuilder builder = mock(EventBuilder.class);
        Map<String, String> details = new HashMap<>();
        when(f.context.getEvent()).thenReturn(builder);
        doAnswer(call -> { if (call.getArgument(1) != null) details.put(call.getArgument(0), call.getArgument(1)); return builder; })
                .when(builder).detail(anyString(), nullable(String.class));
        doAnswer(call -> { details.remove(call.getArgument(0)); return builder; }).when(builder).removeDetail(anyString());
        RiskDecisionHandler handler = new RiskDecisionHandler(f.trace);
        handler.handle(f.context, evaluation(RiskDecision.ALLOW, BigDecimal.ZERO, RiskDataStatus.COMPLETE));
        assertEquals(EVALUATION.toString(), details.get("zt_evaluation_id"));
        Event login = f.event(EventType.LOGIN); login.setDetails(new HashMap<>(details));
        when(f.kcContext.getAuthenticationSession()).thenReturn(null);
        f.trace.authenticationEvent(f.session, login);
        assertEquals(row(f, 0).get("correlation_id"), row(f, 2).get("correlation_id"));
        handler.handleUnavailable(f.context, RiskFailureMode.DENY, "TIMEOUT");
        assertFalse(details.containsKey("zt_evaluation_id"));
        assertNotEquals(row(f, 0).get("correlation_id"), details.get("zt_trace_id"));
        assertEquals(Set.of("zt_trace_id", "zt_subject_tag"), details.keySet());
    }

    private static Map<?, ?> row(Fixture f, int index) throws Exception {
        return JsonSerialization.readValue(f.lines.get(index), Map.class);
    }

    @ParameterizedTest
    @EnumSource(RiskDecision.class)
    void timingUsesExistingCorrelationAndNeverImpliesMfaCompletion(RiskDecision decision) throws Exception {
        Fixture f = new Fixture();
        var evaluation = evaluation(decision, BigDecimal.TEN, RiskDataStatus.COMPLETE);
        new RiskDecisionHandler(f.trace).handle(f.context, evaluation);
        f.trace.riskCallTiming(f.context, evaluation, 1_234_567L);
        Map<?, ?> timing = row(f, 2);
        assertEquals("RISK_CALL_TIMING", timing.get("stage"));
        assertEquals("RISK_RESPONSE_RECEIVED", timing.get("outcome"));
        assertEquals(row(f, 0).get("correlation_id"), timing.get("correlation_id"));
        assertEquals(EVALUATION.toString(), timing.get("evaluation_id"));
        assertEquals(Boolean.TRUE, timing.get("valid_risk_response"));
        assertEquals(new BigDecimal("1.234567"), new BigDecimal(timing.get("risk_call_duration_ms").toString()));
        assertFalse(String.join("", f.lines).contains("MFA_COMPLETED"));
        assertEnforcement(f, decision);
    }

    @Test
    void unavailableTimingHasNoEvaluationIdAndCannotChangeFailSafeDeny() throws Exception {
        Fixture f = new Fixture();
        new RiskDecisionHandler(f.trace).handleUnavailable(f.context, RiskFailureMode.DENY, "TIMEOUT");
        f.trace.riskCallTiming(f.context, null, 10_000L);
        Map<?, ?> timing = row(f, 2);
        assertEquals("RISK_CALL_FAILED", timing.get("outcome"));
        assertEquals(Boolean.FALSE, timing.get("valid_risk_response"));
        assertNull(timing.get("evaluation_id"));
        assertEquals(row(f, 0).get("correlation_id"), timing.get("correlation_id"));
        verify(f.context, never()).success();
        verify(f.context).failure(eq(AuthenticationFlowError.ACCESS_DENIED), any(), anyString(), anyString());
    }

    @Test
    void timingLoggerFailureNeverChangesDeny() {
        Fixture f = new Fixture(line -> { throw new IllegalStateException("sensitive-canary"); });
        var evaluation = evaluation(RiskDecision.DENY, new BigDecimal("75"), RiskDataStatus.COMPLETE);
        new RiskDecisionHandler(f.trace).handle(f.context, evaluation);
        assertDoesNotThrow(() -> f.trace.riskCallTiming(f.context, evaluation, 100));
        assertEnforcement(f, RiskDecision.DENY);
    }

    private static RiskEvaluationResponse evaluation(RiskDecision decision, BigDecimal score, RiskDataStatus status) {
        return new RiskEvaluationResponse(EVALUATION, "subject-person-canary", "auth-session-secret-canary",
                score, switch (decision) {
                    case ALLOW -> RiskLevel.LOW;
                    case STEP_UP_MFA -> RiskLevel.MEDIUM;
                    case DENY -> RiskLevel.HIGH;
                }, decision, status, List.of(RiskReason.TEMPORAL_PROFILE_COLD_START), NOW, 0L);
    }

    private static void assertEnforcement(Fixture f, RiskDecision decision) {
        if (decision == RiskDecision.DENY) {
            verify(f.context).failure(eq(AuthenticationFlowError.ACCESS_DENIED), eq(f.errorPage),
                    eq("risk_policy_denied"), eq("accessDenied"));
            verify(f.context, never()).success();
        } else {
            verify(f.context).success();
            if (decision == RiskDecision.STEP_UP_MFA) assertEquals("true", f.notes.get(RiskAuthenticationNotes.STEP_UP_REQUIRED));
        }
    }

    private static final class Fixture {
        final List<String> lines = new ArrayList<>();
        final Map<String, String> notes = new HashMap<>();
        final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        final AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        final AuthenticationSessionModel auth = mock(AuthenticationSessionModel.class);
        final KeycloakSession session = mock(KeycloakSession.class);
        final KeycloakContext kcContext = mock(KeycloakContext.class);
        final RealmModel realm = mock(RealmModel.class);
        final UserModel user = mock(UserModel.class);
        final ClientModel client = mock(ClientModel.class);
        final Response errorPage = mock(Response.class);
        final RiskEvaluationTrace trace;
        Fixture() { this(null); }
        Fixture(Consumer<String> sink) {
            trace = new RiskEvaluationTrace(sink == null ? lines::add : sink, new byte[32], clock);
            when(context.getAuthenticationSession()).thenReturn(auth);
            when(context.getUser()).thenReturn(user);
            when(context.getRealm()).thenReturn(realm);
            when(auth.getAuthenticatedUser()).thenReturn(user);
            when(user.getId()).thenReturn("subject-person-canary");
            when(realm.getId()).thenReturn("realm-canary");
            when(auth.getClient()).thenReturn(client);
            when(client.getClientId()).thenReturn("zerotrust-spa");
            when(auth.getAuthNote(anyString())).thenAnswer(call -> notes.get(call.getArgument(0)));
            doAnswer(call -> { notes.put(call.getArgument(0), call.getArgument(1)); return null; })
                    .when(auth).setAuthNote(anyString(), anyString());
            doAnswer(call -> { notes.remove(call.getArgument(0)); return null; }).when(auth).removeAuthNote(anyString());
            when(session.getContext()).thenReturn(kcContext);
            when(kcContext.getAuthenticationSession()).thenReturn(auth);
            when(kcContext.getRealm()).thenReturn(realm);
            LoginFormsProvider forms = mock(LoginFormsProvider.class);
            when(context.form()).thenReturn(forms);
            when(forms.setError("accessDenied")).thenReturn(forms);
            when(forms.createErrorPage(Response.Status.FORBIDDEN)).thenReturn(errorPage);
        }
        Event event(EventType type) {
            Event event = new Event(); event.setType(type); event.setClientId("zerotrust-spa");
            event.setUserId(user.getId()); event.setIpAddress("203.0.113.77");
            event.setSessionId("auth-session-secret-canary");
            event.setDetails(Map.of("token", "secret-canary", "redirect_uri", "secret-canary"));
            return event;
        }
    }
}
