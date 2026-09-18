package com.zerotrust.risk.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import com.zerotrust.risk.config.RiskApiSecurityConfig;
import com.zerotrust.risk.config.RiskApiSecurityProperties;
import com.zerotrust.risk.controller.AuthenticationFailureController;
import com.zerotrust.risk.controller.AuthenticationSuccessController;
import com.zerotrust.risk.controller.RiskEvaluationController;
import com.zerotrust.risk.controller.TrustedDeviceController;
import com.zerotrust.risk.domain.*;
import com.zerotrust.risk.service.AuthenticationFailureService;
import com.zerotrust.risk.service.AuthenticationSuccessService;
import com.zerotrust.risk.service.RiskEvaluationService;
import com.zerotrust.risk.service.TrustedDeviceRegistrationService;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest({
        RiskEvaluationController.class,
        TrustedDeviceController.class,
        AuthenticationFailureController.class,
        AuthenticationSuccessController.class
})
@Import(RiskApiSecurityConfig.class)
@EnableConfigurationProperties(RiskApiSecurityProperties.class)
class RiskApiSecurityTests {
    private static final String EVALUATION_PATH = "/internal/v1/risk/evaluations";
    private static final String TRUSTED_DEVICE_PATH = "/internal/v1/trusted-devices";
    private static final String AUTHENTICATION_FAILURE_PATH =
            "/internal/v1/authentication-failures";
    private static final String AUTHENTICATION_SUCCESS_PATH =
            "/internal/v1/authentication-successes";
    private static final String ISSUER = "https://issuer.example/realms/test";
    private static final String BODY = """
            {"subjectId":"student-1","authenticationSessionId":"session-1",
             "clientId":"zerotrust-spa","ipAddress":"203.0.113.10"}
            """;
    private static final String TRUSTED_DEVICE_BODY = """
            {"subjectId":"student-1","deviceId":"device-1"}
            """;
    private static final String AUTHENTICATION_FAILURE_BODY = """
            {"eventId":"event-1","subjectId":"student-1","sourceIp":"203.0.113.10"}
            """;
    private static final String AUTHENTICATION_SUCCESS_BODY = """
            {"eventId":"event-2","subjectId":"student-1","clientId":"zerotrust-spa",
             "authenticatedAt":"2026-09-17T03:00:00Z"}
            """;
    private static final RSAKey KEY;
    private static final HttpServer JWKS;
    static {
        try {
            KEY = new RSAKeyGenerator(2048).keyID("test-key").generate();
            JWKS = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            JWKS.createContext("/jwks", exchange -> {
                byte[] body = new JWKSet(KEY.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.close();
            });
            JWKS.start();
        } catch (Exception exception) { throw new ExceptionInInitializerError(exception); }
    }

    @DynamicPropertySource
    static void config(DynamicPropertyRegistry properties) {
        properties.add("risk.security.issuer-uri", () -> ISSUER);
        properties.add("risk.security.jwk-set-uri", () -> "http://127.0.0.1:" + JWKS.getAddress().getPort() + "/jwks");
        properties.add("risk.security.require-https", () -> false);
        properties.add("risk.security.audience", () -> "zerotrust-risk-api");
        properties.add("risk.security.allowed-client-id", () -> "zerotrust-risk-caller");
    }

    @AfterAll static void stop() { JWKS.stop(0); }
    @Autowired MockMvc mvc;
    @MockitoBean RiskEvaluationService service;
    @MockitoBean TrustedDeviceRegistrationService registrationService;
    @MockitoBean AuthenticationFailureService authenticationFailureService;
    @MockitoBean AuthenticationSuccessService authenticationSuccessService;

    @BeforeEach void evaluation() {
        when(service.evaluate(any())).thenReturn(new RiskEvaluation(UUID.randomUUID(), null,
                RiskLevel.HIGH, RiskDecision.DENY, RiskDataStatus.NOT_EVALUATED,
                List.of(RiskReason.BLOCKED_IP_ADDRESS), Instant.now()));
    }

    @Test void missingAndMalformedTokensAre401AndDoNotReachService() throws Exception {
        mvc.perform(post(EVALUATION_PATH).contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("UNAUTHORIZED"));
        mvc.perform(post(TRUSTED_DEVICE_PATH).contentType(MediaType.APPLICATION_JSON)
                        .content(TRUSTED_DEVICE_BODY))
                .andExpect(status().isUnauthorized());
        mvc.perform(post(AUTHENTICATION_FAILURE_PATH).contentType(MediaType.APPLICATION_JSON)
                        .content(AUTHENTICATION_FAILURE_BODY))
                .andExpect(status().isUnauthorized());
        mvc.perform(post(AUTHENTICATION_SUCCESS_PATH).contentType(MediaType.APPLICATION_JSON)
                        .content(AUTHENTICATION_SUCCESS_BODY))
                .andExpect(status().isUnauthorized());
        call("not-a-jwt").andExpect(status().isUnauthorized());
        verify(service, never()).evaluate(any());
        verifyNoInteractions(registrationService);
        verifyNoInteractions(authenticationFailureService);
        verifyNoInteractions(authenticationSuccessService);
    }

    @Test void signedServiceTokenReachesEvaluationAndDenyIsStillHttp200() throws Exception {
        call(sign(claims(), KEY)).andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("DENY"))
                .andExpect(header().doesNotExist("Set-Cookie"));
        verify(service).evaluate(any());
    }

    @Test void wrongIssuerAudienceExpiredFutureAndMissingExpiryAre401() throws Exception {
        for (JWTClaimsSet.Builder builder : List.of(
                claims().issuer("https://attacker.example"), claims().audience("zerotrust-api"),
                claims().expirationTime(Date.from(Instant.now().minusSeconds(120))),
                claims().notBeforeTime(Date.from(Instant.now().plusSeconds(120))),
                claims().expirationTime(null))) {
            call(sign(builder, KEY)).andExpect(status().isUnauthorized());
        }
        verify(service, never()).evaluate(any());
    }

    @Test void forgedSignatureIs401() throws Exception {
        RSAKey attacker = new RSAKeyGenerator(2048).keyID("test-key").generate();
        call(sign(claims(), attacker)).andExpect(status().isUnauthorized());
        verify(service, never()).evaluate(any());
    }

    @Test void wrongCallerIncludingPortalAndProvisionerIs403() throws Exception {
        for (String caller : List.of("zerotrust-spa", "zerotrust-provisioner", "other-client")) {
            call(sign(claims().claim("azp", caller), KEY)).andExpect(status().isForbidden());
        }
        call(sign(claims().claim("azp", null), KEY)).andExpect(status().isForbidden());
        verify(service, never()).evaluate(any());
    }

    @Test void RealmRoleOtherClientRoleAndMalformedRolesCannotGrantAccess() throws Exception {
        for (Object resource : List.of(Map.of(), "invalid", Map.of("other-api", Map.of("roles", List.of("risk:evaluate"))),
                Map.of("zerotrust-risk-api", Map.of("roles", "risk:evaluate")))) {
            call(sign(claims().claim("resource_access", resource)
                    .claim("realm_access", Map.of("roles", List.of("risk:evaluate", "ADMIN"))), KEY))
                    .andExpect(status().isForbidden());
        }
        verify(service, never()).evaluate(any());
    }

    @Test void authorizedInvalidBodyIs400() throws Exception {
        mvc.perform(post(EVALUATION_PATH).header("Authorization", "Bearer " + sign(claims(), KEY))
                .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
        verify(service, never()).evaluate(any());
    }

    @Test void eachWriteEndpointRequiresItsDedicatedClientRole() throws Exception {
        String evaluationToken = sign(claims(), KEY);
        String deviceWriteToken = sign(claimsWithRoles(
                RiskJwtAuthenticationConverter.DEVICE_WRITE_AUTHORITY
        ), KEY);
        String eventsWriteToken = sign(claimsWithRoles(
                RiskJwtAuthenticationConverter.EVENTS_WRITE_AUTHORITY
        ), KEY);

        callTrustedDevice(evaluationToken).andExpect(status().isForbidden());
        call(deviceWriteToken).andExpect(status().isForbidden());
        callAuthenticationFailure(evaluationToken).andExpect(status().isForbidden());
        callAuthenticationFailure(deviceWriteToken).andExpect(status().isForbidden());
        callAuthenticationSuccess(evaluationToken).andExpect(status().isForbidden());
        callAuthenticationSuccess(deviceWriteToken).andExpect(status().isForbidden());
        callTrustedDevice(deviceWriteToken)
                .andExpect(status().isNoContent())
                .andExpect(header().doesNotExist("Set-Cookie"));
        callAuthenticationFailure(eventsWriteToken)
                .andExpect(status().isNoContent())
                .andExpect(header().doesNotExist("Set-Cookie"));
        callAuthenticationSuccess(eventsWriteToken)
                .andExpect(status().isNoContent())
                .andExpect(header().doesNotExist("Set-Cookie"));
        call(eventsWriteToken).andExpect(status().isForbidden());
        callTrustedDevice(eventsWriteToken).andExpect(status().isForbidden());

        verify(registrationService).trustAfterMfa("student-1", "device-1");
        verify(authenticationFailureService).recordFailure(
                "event-1",
                "student-1",
                "203.0.113.10"
        );
        verify(authenticationSuccessService).recordSuccess(
                "event-2",
                "student-1",
                "zerotrust-spa",
                Instant.parse("2026-09-17T03:00:00Z")
        );
        verify(service, never()).evaluate(any());
    }

    @Test void authenticationFailureEndpointValidatesEventAndIp() throws Exception {
        String eventsWriteToken = sign(claimsWithRoles(
                RiskJwtAuthenticationConverter.EVENTS_WRITE_AUTHORITY
        ), KEY);

        mvc.perform(post(AUTHENTICATION_FAILURE_PATH)
                        .header("Authorization", "Bearer " + eventsWriteToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"eventId":"", "sourceIp":"not-an-ip"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.eventId").exists())
                .andExpect(jsonPath("$.fieldErrors.sourceIp").exists());

        verifyNoInteractions(authenticationFailureService);
    }

    @Test void authenticationSuccessEndpointValidatesRequiredTemporalFields() throws Exception {
        String eventsWriteToken = sign(claimsWithRoles(
                RiskJwtAuthenticationConverter.EVENTS_WRITE_AUTHORITY
        ), KEY);

        mvc.perform(post(AUTHENTICATION_SUCCESS_PATH)
                        .header("Authorization", "Bearer " + eventsWriteToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"eventId":"", "subjectId":"", "clientId":""}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.eventId").exists())
                .andExpect(jsonPath("$.fieldErrors.subjectId").exists())
                .andExpect(jsonPath("$.fieldErrors.clientId").exists())
                .andExpect(jsonPath("$.fieldErrors.authenticatedAt").exists());

        verifyNoInteractions(authenticationSuccessService);
    }

    @Test void otherPathsAndMethodsAreDeniedAndCorsIsNotEnabled() throws Exception {
        String token = sign(claims(), KEY);
        mvc.perform(get(EVALUATION_PATH).header("Authorization", "Bearer " + token)).andExpect(status().isForbidden());
        mvc.perform(get("/actuator/info").header("Authorization", "Bearer " + token)).andExpect(status().isForbidden());
        mvc.perform(options(EVALUATION_PATH).header("Origin", "https://untrusted.example")
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(status().isUnauthorized()).andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }

    private ResultActions call(String token) throws Exception {
        return mvc.perform(post(EVALUATION_PATH).header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON).content(BODY));
    }

    private ResultActions callTrustedDevice(String token) throws Exception {
        return mvc.perform(post(TRUSTED_DEVICE_PATH).header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON).content(TRUSTED_DEVICE_BODY));
    }

    private ResultActions callAuthenticationFailure(String token) throws Exception {
        return mvc.perform(post(AUTHENTICATION_FAILURE_PATH)
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(AUTHENTICATION_FAILURE_BODY));
    }

    private ResultActions callAuthenticationSuccess(String token) throws Exception {
        return mvc.perform(post(AUTHENTICATION_SUCCESS_PATH)
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(AUTHENTICATION_SUCCESS_BODY));
    }

    private static JWTClaimsSet.Builder claims() {
        return claimsWithRoles(RiskJwtAuthenticationConverter.EVALUATE_AUTHORITY);
    }

    private static JWTClaimsSet.Builder claimsWithRoles(String... roles) {
        return new JWTClaimsSet.Builder().issuer(ISSUER).subject("service-account-id")
                .audience("zerotrust-risk-api").issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .claim("azp", "zerotrust-risk-caller")
                .claim("resource_access", Map.of("zerotrust-risk-api", Map.of("roles", List.of(roles))));
    }
    private static String sign(JWTClaimsSet.Builder claims, RSAKey key) throws Exception {
        SignedJWT token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims.build());
        token.sign(new RSASSASigner(key));
        return token.serialize();
    }
}
