package com.zerotrust.risk.audit.http;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

/** Live Tomcat/JWT/JPA for status and security. Synthetic dispatch controls are separately labelled. */
@EnabledIfSystemProperty(named = "qa.http.audit", matches = "true")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Import({HttpDispatchTrace.class, RiskErrorDispatchHttpRegressionTests.SecurityProbe.class})
class RiskErrorDispatchHttpRegressionTests extends HttpAuditSupport {
    @Autowired WebApplicationContext web;
    private static final String SENSITIVE = "fix07-private-fault-marker";
    @AfterAll static void closeFixture() { HttpJwtFixture.JWKS.stop(0); }
    @BeforeEach void clearObservation() { HttpDispatchTrace.RECORDS.clear(); SecurityProbe.ENTRIES.clear(); }

    @ParameterizedTest @ValueSource(strings = {
            "malformed", "array", "number", "boolean", "string", "object-subject", "missing-required", "null-body", "uuid-path"})
    void liveInvalidBodiesKeep400WithoutMutation(String variant) throws Exception {
        String path = REG, body = reg(id(), 0); boolean error = true;
        switch (variant) {
            case "malformed" -> body = "{";
            case "array" -> body = "[]";
            case "number" -> body = "42";
            case "boolean" -> body = "true";
            case "string" -> body = "\"" + SENSITIVE + "\"";
            case "object-subject" -> body = "{\"subjectId\":{},\"deviceId\":\"qa-device\",\"trustGeneration\":0}";
            case "missing-required" -> { body = json(Map.of("subjectId", id(), "deviceId", DEVICE)); error = false; }
            case "null-body" -> body = "null";
            case "uuid-path" -> { path = revoke("not-a-uuid"); body = operation(id(), "qa-admin"); }
        }
        var before = db(); var response = post(path, allowed(path), body); unchanged(before);
        assertError(response, 400, path);
        if (error) errorDispatch(400); else assertThat(HttpDispatchTrace.RECORDS).noneMatch(d -> d.type() == DispatcherType.ERROR);
    }

    @ParameterizedTest @ValueSource(strings = {"data-access", "service-runtime", "unexpected-runtime"})
    void liveInternalFaultIs500AndNeverDisclosesItsMessage(String variant) throws Exception {
        RuntimeException failure = switch (variant) {
            case "data-access" -> new DataRetrievalFailureException(SENSITIVE);
            case "service-runtime" -> new IllegalStateException(SENSITIVE);
            default -> new ArithmeticException(SENSITIVE);
        };
        doThrow(failure).when(redis).recordFailure(anyString(), nullable(String.class), anyString());
        var before = db();
        var response = post(FAIL + "?trace=true&message=true", allowed(FAIL), body(FAIL, id()));
        assertThat(db()).isEqualTo(before); assertThat(writes.get()).isZero();
        assertThat(events).isEmpty(); assertThat(subjects).isEmpty(); assertThat(ips).isEmpty();
        verify(redis).recordFailure(anyString(), nullable(String.class), anyString());
        assertError(response, 500, FAIL); errorDispatch(500);
    }

    @ParameterizedTest @ValueSource(strings = {"none", "valid", "malformed"})
    void liveDirectErrorRequestNeverReceivesInternalDispatchPermission(String tokenKind) throws Exception {
        String token = tokenKind.equals("none") ? null : tokenKind.equals("valid") ? allowed(EVAL) : "x.y.z";
        var before = db();
        var response = call("GET", "/error?dispatcherType=ERROR&jakarta.servlet.error.status_code=500", token, "",
                "X-Dispatcher-Type", "ERROR", "X-Original-URI", REG);
        assertError(response, tokenKind.equals("valid") ? 403 : 401, "/error"); unchanged(before);
        await().untilAsserted(() -> assertThat(HttpDispatchTrace.RECORDS).anyMatch(d -> d.type() == DispatcherType.REQUEST && d.uri().equals("/error")));
        assertThat(HttpDispatchTrace.RECORDS).noneMatch(d -> d.type() == DispatcherType.ERROR);
    }

    @ParameterizedTest @ValueSource(strings = {"headers", "parameters"})
    void liveDispatchSpoofingCannotAuthorizeBusinessMutation(String variant) throws Exception {
        String path = variant.equals("parameters") ? REG + "?dispatcherType=ERROR&jakarta.servlet.error.request_uri=/error" : REG;
        var before = db();
        var response = call("POST", path, HttpJwtFixture.token(HttpJwtFixture.CALLER, "risk:evaluate"), "{",
                "X-Dispatcher-Type", "ERROR", "X-Forwarded-Proto", "https");
        assertError(response, 403, REG); unchanged(before);
        assertThat(HttpDispatchTrace.RECORDS).noneMatch(d -> d.type() == DispatcherType.ERROR);
    }

    @ParameterizedTest @ValueSource(strings = {"evaluation", "registration", "failure", "success", "revoke", "completion"})
    void liveCorrectServiceCallerAndRoleStillReachOnlyTheirAuthorizedOperation(String endpoint) throws Exception {
        String subject = id(), path;
        String payload;
        switch (endpoint) {
            case "evaluation" -> { path = EVAL; payload = evaluation(subject, "10.1.2.3"); }
            case "registration" -> { path = REG; payload = reg(subject, 0); }
            case "failure" -> { path = FAIL; payload = body(path, subject); }
            case "success" -> { path = SUCCESS; payload = body(path, subject); }
            case "revoke" -> { path = revoke(subject); payload = operation(id(), "qa-admin"); }
            default -> {
                String reset = revoke(subject); payload = operation(id(), "qa-admin");
                assertThat(post(reset, allowed(reset), payload).statusCode()).isEqualTo(204);
                path = reset + "/completion";
            }
        }
        var response = post(path, allowed(path), payload);
        assertThat(response.statusCode()).isEqualTo(endpoint.equals("evaluation") ? 200 : 204);
        assertThat(HttpJwtFixture.FETCHES.get()).isPositive();
        await().untilAsserted(() -> assertThat(SecurityProbe.ENTRIES).anyMatch(e -> e.type() == DispatcherType.REQUEST && e.authentication().equals("JwtAuthenticationToken")));
        // JWT.sub is a service account; delegated target subjects remain different synthetic identities.
    }

    @Test void liveBusinessConflictRemains409WithoutErrorRedispatch() throws Exception {
        String subject = id(); trusted(subject); String reset = revoke(subject);
        assertThat(post(reset, allowed(reset), operation(id(), "qa-admin")).statusCode()).isEqualTo(204);
        var before = db(); var response = post(REG, allowed(REG), reg(subject, 0));
        assertError(response, 409, REG); assertThat(db()).isEqualTo(before);
        assertThat(HttpDispatchTrace.RECORDS).noneMatch(d -> d.type() == DispatcherType.ERROR);
        assertThat(node(response).path("error").asText()).isEqualTo("DEVICE_TRUST_REJECTED");
    }

    @Test void nonexistentRouteKeepsDefaultDenyAndUnknownEnumIsNotAnApiEnum() throws Exception {
        var before = db(); assertError(call("GET", "/not-a-risk-route", allowed(EVAL), ""), 403, "/not-a-risk-route"); unchanged(before);
        String subject = id();
        // Production request DTO has no enum field; unknown properties are ignored by its existing contract.
        String payload = reg(subject, 0).replace("}", ",\"decision\":\"NOT_AN_ENUM\"}");
        assertThat(post(REG, allowed(REG), payload).statusCode()).isEqualTo(204);
        assertThat(devices.findAllBySubjectId(subject)).hasSize(1);
    }

    @ParameterizedTest @CsvSource({
            "ERROR,/error,500", "ERROR,/internal/v1/trusted-devices,401",
            "FORWARD,/error,403", "FORWARD,/internal/v1/trusted-devices,401", "INCLUDE,/error,403"})
    void syntheticDispatchControlRestrictsTheExemptionToErrorRendering(String type, String path, int expected) throws Exception {
        var before = db();
        if (!type.equals("ERROR") && path.equals("/error")) {
            authenticatedNestedDispatch(type, expected); unchanged(before); return;
        }
        var request = path.equals("/error") ? get(path) : org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post(path)
                .content(reg(id(), 0)).contentType("application/json");
        request.with(r -> { r.setDispatcherType(DispatcherType.valueOf(type)); r.setServletPath(path); return r; });
        request.requestAttr(RequestDispatcher.ERROR_STATUS_CODE, 500).requestAttr(RequestDispatcher.ERROR_REQUEST_URI, FAIL);
        if (!type.equals("ERROR") && path.equals("/error")) request.header("Authorization", "Bearer " + allowed(EVAL));
        // Apply the real chain explicitly to each synthetic dispatch, including FORWARD/INCLUDE.
        var mvc = MockMvcBuilders.webAppContextSetup(web).apply(springSecurity()).build();
        var response = mvc.perform(request).andReturn().getResponse();
        System.out.println("FIX07 SYNTHETIC DISPATCH type=" + type + " path=" + path + " status=" + response.getStatus());
        assertThat(response.getStatus()).isEqualTo(expected); unchanged(before);
        assertThat(response.getContentAsString()).doesNotContain(SENSITIVE, "stackTrace", "java.lang.");
    }

    private void authenticatedNestedDispatch(String type, int expected) throws Exception {
        authenticatedNestedDispatch(type, "/error", expected);
    }

    @Test void authenticatedErrorToBusinessEndpointStillRequiresItsOwnRole() throws Exception {
        var before = db(); authenticatedNestedDispatch("ERROR", REG, 403); unchanged(before);
    }

    private void authenticatedNestedDispatch(String type, String path, int expected) throws Exception {
        // An authenticated FORWARD/INCLUDE carries the context of its original REQUEST, not a new login.
        var initial = new org.springframework.mock.web.MockHttpServletRequest(web.getServletContext());
        initial.setMethod("POST"); initial.setRequestURI(EVAL); initial.setServletPath(EVAL);
        initial.addHeader("Authorization", "Bearer " + allowed(EVAL));
        var dispatched = new org.springframework.mock.web.MockHttpServletRequest(web.getServletContext());
        dispatched.setMethod(path.equals("/error") ? "GET" : "POST"); dispatched.setRequestURI(path); dispatched.setServletPath(path);
        dispatched.setDispatcherType(DispatcherType.valueOf(type));
        var response = new org.springframework.mock.web.MockHttpServletResponse();
        Filter security = web.getBean("springSecurityFilterChain", Filter.class);
        try {
            security.doFilter(initial, new org.springframework.mock.web.MockHttpServletResponse(), (request, ignored) -> {
                assertThat(SecurityContextHolder.getContext().getAuthentication())
                        .isInstanceOf(org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken.class);
                java.util.Collections.list(request.getAttributeNames()).forEach(name -> dispatched.setAttribute(name, request.getAttribute(name)));
                security.doFilter(dispatched, response, (targetRequest, targetResponse) -> ((HttpServletResponse) targetResponse).setStatus(500));
            });
        } finally { SecurityContextHolder.clearContext(); }
        System.out.println("FIX07 AUTHENTICATED SYNTHETIC DISPATCH type=" + type + " path=" + path + " status=" + response.getStatus());
        assertThat(response.getStatus()).isEqualTo(expected);
        assertThat(response.getContentAsString()).doesNotContain(SENSITIVE, "stackTrace", "java.lang.");
    }

    private void assertError(HttpResponse<String> response, int status, String path) throws Exception {
        assertThat(response.statusCode()).isEqualTo(status);
        var body = node(response); assertThat(body.path("status").asInt()).isEqualTo(status); assertThat(body.path("path").asText()).isEqualTo(path);
        assertThat(response.body()).doesNotContain(SENSITIVE, "stackTrace", "java.lang.", "org.springframework.", "SELECT ", "INSERT ", "access_token");
        assertThat(body.has("trace")).isFalse(); assertThat(body.has("exception")).isFalse();
    }
    private void errorDispatch(int status) {
        await().untilAsserted(() -> assertThat(HttpDispatchTrace.RECORDS).anyMatch(d -> d.type() == DispatcherType.ERROR
                && d.uri().equals("/error") && Integer.valueOf(status).equals(d.originalStatus()) && d.responseStatus() == status));
        await().untilAsserted(() -> assertThat(SecurityProbe.ENTRIES).anyMatch(e -> e.type() == DispatcherType.ERROR && e.servletPath().equals("/error")));
    }
    @TestConfiguration(proxyBeanMethods = false)
    static class SecurityProbe {
        record Entry(DispatcherType type, String servletPath, String authentication) {}
        static final List<Entry> ENTRIES = new CopyOnWriteArrayList<>();
        @Bean FilterRegistrationBean<Filter> postSecurityProbe() {
            Filter probe = (request, response, chain) -> {
                var auth = SecurityContextHolder.getContext().getAuthentication();
                var row = new Entry(request.getDispatcherType(), ((HttpServletRequest) request).getServletPath(), auth == null ? "none" : auth.getClass().getSimpleName());
                ENTRIES.add(row); System.out.println("FIX07 SECURITY " + row); chain.doFilter(request, response);
            };
            var bean = new FilterRegistrationBean<>(probe); bean.setOrder(-99);
            bean.setDispatcherTypes(DispatcherType.REQUEST, DispatcherType.ERROR); return bean;
        }
    }
}
