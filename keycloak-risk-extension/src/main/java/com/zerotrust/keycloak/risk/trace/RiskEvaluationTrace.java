package com.zerotrust.keycloak.risk.trace;

import com.zerotrust.keycloak.risk.dto.RiskEvaluationResponse;
import com.zerotrust.keycloak.risk.policy.RiskAuthenticationNotes;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

/** Best-effort, allowlisted telemetry. No trace value participates in authentication. */
public final class RiskEvaluationTrace {
    public static final String TRACE_ID = "zerotrust.trace.id";
    public static final String SUBJECT_TAG = "zerotrust.trace.subject-tag";
    private static final String EVENT_TRACE_ID = "zt_trace_id";
    private static final String EVENT_EVALUATION_ID = "zt_evaluation_id";
    private static final String EVENT_SUBJECT_TAG = "zt_subject_tag";
    private static final Logger LOG = Logger.getLogger(RiskEvaluationTrace.class);
    // A private mapper keeps explicit null scores without changing Keycloak's API serializer.
    private static final ObjectMapper JSON = JsonSerialization.mapper.copy()
            .setDefaultPropertyInclusion(JsonInclude.Include.ALWAYS);
    public static final RiskEvaluationTrace DEFAULT = new RiskEvaluationTrace(
            line -> LOG.info("ZEROTRUST_RISK_TRACE " + line), randomKey(), Clock.systemUTC());

    public enum Stage { RISK_EVALUATION, RISK_CALL_TIMING, KEYCLOAK_ENFORCEMENT, MFA_GATE, MFA_FORM,
        DEVICE_REGISTRATION, AUTHENTICATION_EVENT }
    public enum Outcome { EVALUATED, RISK_STEP_PASSED, STEP_UP_REQUIRED, ACCESS_DENIED,
        SERVICE_UNAVAILABLE_DENY, SERVICE_UNAVAILABLE_STEP_UP, MFA_SUBFLOW_SELECTED,
        MFA_SUBFLOW_NOT_SELECTED, MFA_DEFERRED_TO_REQUIRED_ACTION, CHALLENGE_RENDERED,
        MFA_INPUT_REJECTED, NOT_ELIGIBLE, ENROLLMENT_PENDING, REGISTERED_204,
        COOKIE_ISSUED, REGISTRATION_REJECTED, REGISTRATION_UNAVAILABLE,
        REGISTRATION_ERROR, LOGIN_SUCCESS, LOGIN_ERROR, SSO_COOKIE_LOGIN,
        REFRESH_SUCCESS_NO_BROWSER_FLOW, REFRESH_ERROR_NO_BROWSER_FLOW,
        RISK_RESPONSE_RECEIVED, RISK_CALL_FAILED }

    private final Consumer<String> sink;
    private final byte[] key;
    private final Clock clock;

    public RiskEvaluationTrace(Consumer<String> sink, byte[] key, Clock clock) {
        this.sink = java.util.Objects.requireNonNull(sink);
        if (key == null || key.length < 32) throw new IllegalArgumentException("Trace key needs 256 bits");
        this.key = key.clone();
        this.clock = java.util.Objects.requireNonNull(clock);
    }

    public void evaluation(AuthenticationFlowContext context, RiskEvaluationResponse evaluation) {
        safely(() -> {
            begin(context);
            Map<String, Object> row = base(context.getAuthenticationSession(), clientId(context),
                    Stage.RISK_EVALUATION, Outcome.EVALUATED);
            row.put("evaluation_id", evaluation.evaluationId().toString());
            row.put("evaluated_at", evaluation.evaluatedAt().toString());
            row.put("risk_score", evaluation.riskScore());
            row.put("risk_level", evaluation.riskLevel().name());
            row.put("decision", evaluation.decision().name());
            row.put("data_status", evaluation.dataStatus().name());
            row.put("reason_codes", evaluation.reasons().stream().map(Enum::name).toList());
            row.put("evaluation_source", "RISK_SERVICE_RESPONSE");
            write(row);
        });
    }

    public void unavailable(AuthenticationFlowContext context, String failureType, boolean deny) {
        safely(() -> {
            begin(context);
            Map<String, Object> row = base(context.getAuthenticationSession(), clientId(context),
                    Stage.RISK_EVALUATION, deny ? Outcome.SERVICE_UNAVAILABLE_DENY
                            : Outcome.SERVICE_UNAVAILABLE_STEP_UP);
            // No evaluation was received: never invent a HIGH score or evaluation ID.
            row.put("evaluation_id", null);
            row.put("risk_score", null);
            row.put("risk_level", null);
            row.put("data_status", null);
            row.put("decision", deny ? "DENY" : "STEP_UP_MFA");
            row.put("evaluation_source", "NO_VALID_RISK_RESPONSE");
            row.put("failure_type", safeFailure(failureType));
            write(row);
        });
    }

    public void observe(AuthenticationFlowContext context, Stage stage, Outcome outcome) {
        safely(() -> {
            attachEvent(context);
            write(base(context.getAuthenticationSession(), clientId(context), stage, outcome));
        });
    }

    /** Called after enforcement so the existing evaluation correlation is already established.
     * This duration includes client creation/token acquisition/retries/validation, not human OTP.
     */
    public void riskCallTiming(AuthenticationFlowContext context, RiskEvaluationResponse evaluation, long nanos) {
        safely(() -> {
            Map<String, Object> row = base(context.getAuthenticationSession(), clientId(context),
                    Stage.RISK_CALL_TIMING, evaluation == null ? Outcome.RISK_CALL_FAILED : Outcome.RISK_RESPONSE_RECEIVED);
            row.put("evaluation_id", evaluation == null ? null : evaluation.evaluationId().toString());
            row.put("valid_risk_response", evaluation != null);
            row.put("risk_call_duration_ms", java.math.BigDecimal.valueOf(Math.max(0, nanos), 6));
            write(row);
        });
    }

    public void form(AuthenticationSessionModel auth, Stage stage, Outcome outcome) {
        safely(() -> {
            if (auth != null && uuid(auth.getAuthNote(TRACE_ID)) != null) {
                write(base(auth, auth.getClient() == null ? null : auth.getClient().getClientId(), stage, outcome));
            }
        });
    }

    /** Only actual Keycloak execution status; a requested/challenged OTP is not success. */
    public static String mfaExecution(AuthenticationSessionModel auth, RealmModel realm) {
        if (auth == null || realm == null || auth.getExecutionStatus() == null) return "NOT_OBSERVED";
        for (Map.Entry<String, AuthenticationSessionModel.ExecutionStatus> entry : auth.getExecutionStatus().entrySet()) {
            AuthenticationExecutionModel execution = realm.getAuthenticationExecutionById(entry.getKey());
            if (execution == null || entry.getValue() != AuthenticationSessionModel.ExecutionStatus.SUCCESS) continue;
            if ("auth-otp-form".equals(execution.getAuthenticator())) return "OTP_EXECUTION_SUCCESS";
            if ("auth-recovery-authn-code-form".equals(execution.getAuthenticator())) return "RECOVERY_EXECUTION_SUCCESS";
        }
        return "NOT_OBSERVED";
    }

    public void authenticationEvent(KeycloakSession session, Event event) {
        safely(() -> {
            // Scope is telemetry for this Portal, not an authorization rule.
            if (event == null || !"zerotrust-spa".equals(event.getClientId())) return;
            EventType type = event.getType();
            boolean refresh = type == EventType.REFRESH_TOKEN || type == EventType.REFRESH_TOKEN_ERROR;
            if (!refresh && type != EventType.LOGIN && type != EventType.LOGIN_ERROR) return;
            AuthenticationSessionModel auth = !refresh && session.getContext() != null
                    ? session.getContext().getAuthenticationSession() : null;
            // Never associate an unrelated context with a user/client event.
            if (auth != null && (auth.getClient() == null
                    || !event.getClientId().equals(auth.getClient().getClientId())
                    || auth.getAuthenticatedUser() == null
                    || !java.util.Objects.equals(event.getUserId(), auth.getAuthenticatedUser().getId()))) auth = null;
            boolean sso = auth != null && uuid(auth.getAuthNote(TRACE_ID)) == null
                    && Boolean.parseBoolean(auth.getAuthNote(AuthenticationManager.SSO_AUTH));
            Outcome outcome = refresh ? (type == EventType.REFRESH_TOKEN
                    ? Outcome.REFRESH_SUCCESS_NO_BROWSER_FLOW : Outcome.REFRESH_ERROR_NO_BROWSER_FLOW)
                    : type == EventType.LOGIN_ERROR ? Outcome.LOGIN_ERROR
                    : sso ? Outcome.SSO_COOKIE_LOGIN : Outcome.LOGIN_SUCCESS;
            Map<String, Object> row = base(auth, event.getClientId(), Stage.AUTHENTICATION_EVENT, outcome);
            Map<String, String> details = event.getDetails();
            if (!refresh && row.get("correlation_id") == null && details != null) {
                row.put("correlation_id", uuid(details.get(EVENT_TRACE_ID)));
                row.put("evaluation_id", uuid(details.get(EVENT_EVALUATION_ID)));
                row.put("subject_tag", tag(details.get(EVENT_SUBJECT_TAG)));
            }
            row.put("risk_execution", refresh ? "NOT_RUN_REFRESH" : sso ? "NOT_RUN_SSO_COOKIE"
                    : row.get("correlation_id") == null ? "NOT_OBSERVED" : "CORRELATED");
            row.put("mfa_execution", mfaExecution(auth, session.getContext() == null
                    ? null : session.getContext().getRealm()));
            write(row);
        });
    }

    public void registrationReached(AuthenticationFlowContext context) {
        safely(() -> {
            attachEvent(context);
            Map<String, Object> row = base(context.getAuthenticationSession(), clientId(context),
                    Stage.MFA_GATE, Outcome.RISK_STEP_PASSED);
            row.put("mfa_execution", mfaExecution(context.getAuthenticationSession(), context.getRealm()));
            write(row);
        });
    }

    private void begin(AuthenticationFlowContext context) throws Exception {
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        auth.setAuthNote(TRACE_ID, UUID.randomUUID().toString());
        auth.removeAuthNote(SUBJECT_TAG);
        if (context.getUser() != null && context.getRealm() != null) {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            String scopedSubject = context.getRealm().getId() + "\u0000" + context.getUser().getId();
            auth.setAuthNote(SUBJECT_TAG, HexFormat.of().formatHex(
                    mac.doFinal(scopedSubject.getBytes(StandardCharsets.UTF_8)), 0, 16));
        }
        attachEvent(context);
    }

    private static void attachEvent(AuthenticationFlowContext context) {
        if (context.getEvent() == null) return;
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        // EventBuilder.detail(null) leaves an old value untouched; explicitly clear it.
        context.getEvent().removeDetail(EVENT_TRACE_ID);
        context.getEvent().removeDetail(EVENT_EVALUATION_ID);
        context.getEvent().removeDetail(EVENT_SUBJECT_TAG);
        context.getEvent().detail(EVENT_TRACE_ID, uuid(auth.getAuthNote(TRACE_ID)));
        context.getEvent().detail(EVENT_EVALUATION_ID, uuid(auth.getAuthNote(RiskAuthenticationNotes.EVALUATION_ID)));
        context.getEvent().detail(EVENT_SUBJECT_TAG, tag(auth.getAuthNote(SUBJECT_TAG)));
    }

    private Map<String, Object> base(AuthenticationSessionModel auth, String client, Stage stage, Outcome outcome) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("schema_version", 1);
        row.put("at", Instant.now(clock).toString());
        row.put("stage", stage.name());
        row.put("outcome", outcome.name());
        row.put("correlation_id", auth == null ? null : uuid(auth.getAuthNote(TRACE_ID)));
        row.put("evaluation_id", auth == null ? null : uuid(auth.getAuthNote(RiskAuthenticationNotes.EVALUATION_ID)));
        row.put("subject_tag", auth == null ? null : tag(auth.getAuthNote(SUBJECT_TAG)));
        row.put("client_id", client != null && client.matches("[A-Za-z0-9_.:-]{1,80}") ? client : null);
        return row;
    }

    private static String clientId(AuthenticationFlowContext context) {
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        return auth == null || auth.getClient() == null ? null : auth.getClient().getClientId();
    }

    private static String uuid(String value) {
        if (value == null || !value.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")) return null;
        return UUID.fromString(value).toString();
    }

    private static String tag(String value) {
        return value != null && value.matches("[0-9a-f]{32}") ? value : null;
    }

    private static String safeFailure(String value) {
        if (value == null) return "UNSPECIFIED";
        return switch (value) {
            case "SERIALIZATION_FAILURE", "CONNECTION_FAILURE", "TIMEOUT", "INTERRUPTED",
                 "HTTP_ERROR", "INVALID_RESPONSE", "INTERNAL_ERROR", "UNEXPECTED_ACTION" -> value;
            default -> "UNSPECIFIED";
        };
    }

    private void write(Map<String, Object> row) throws Exception {
        sink.accept(JSON.writeValueAsString(row));
    }

    private static byte[] randomKey() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private static void safely(TraceAction action) {
        try { action.run(); }
        catch (Exception | LinkageError ignored) {
            // Telemetry failure cannot change DENY, MFA, trust registration or login.
            // Do not log exception messages: they may contain authentication context.
        }
    }

    @FunctionalInterface private interface TraceAction { void run() throws Exception; }
}
