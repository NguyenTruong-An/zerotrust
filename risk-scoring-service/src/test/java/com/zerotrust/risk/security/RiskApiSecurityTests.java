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
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
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
        ,com.zerotrust.risk.controller.TrustedDeviceRevocationController.class
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
            {"subjectId":"student-1","deviceId":"device-1","trustGeneration":0}
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
    @MockitoBean com.zerotrust.risk.service.DeviceTrustLifecycle lifecycle;
    @MockitoBean TrustedDeviceRegistrationService registrationService;
    @MockitoBean AuthenticationFailureService authenticationFailureService;
    @MockitoBean AuthenticationSuccessService authenticationSuccessService;

    @BeforeEach void evaluation() {
        when(lifecycle.snapshot(any())).thenReturn(new com.zerotrust.risk.service.DeviceTrustLifecycle.Snapshot(0, false));
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

        verify(registrationService).trustAfterMfa("student-1", "device-1", 0);
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

    @Test void authorizedRiskAttemptEchoesItsNonceWithoutChangingEvaluationCorrelation() throws Exception {
        String nonce = UUID.randomUUID().toString();
        mvc.perform(post(EVALUATION_PATH).header("Authorization", "Bearer " + sign(claims(), KEY))
                .header("X-ZeroTrust-Risk-Request", nonce).contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isOk()).andExpect(header().string("X-ZeroTrust-Risk-Request", nonce))
                .andExpect(jsonPath("$.subjectId").value("student-1"))
                .andExpect(jsonPath("$.authenticationSessionId").value("session-1"))
                .andExpect(jsonPath("$.decision").value("DENY"));
    }

    @Test void invalidOrDuplicateAttemptNonceIsRejectedBeforeSecurityStateWork() throws Exception {
        String token = sign(claims(), KEY);
        for (String nonce : List.of("not-a-uuid", "untrusted-secret-canary", "")) {
            mvc.perform(post(EVALUATION_PATH).header("Authorization", "Bearer " + token)
                    .header("X-ZeroTrust-Risk-Request", nonce).contentType(MediaType.APPLICATION_JSON).content(BODY))
                    .andExpect(status().isBadRequest()).andExpect(content().string(
                            org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("untrusted-secret-canary"))));
        }
        mvc.perform(post(EVALUATION_PATH).header("Authorization", "Bearer " + token)
                .header("X-ZeroTrust-Risk-Request", UUID.randomUUID().toString(), UUID.randomUUID().toString())
                .contentType(MediaType.APPLICATION_JSON).content(BODY)).andExpect(status().isBadRequest());
        verifyNoInteractions(service, lifecycle);
    }

    @Test void nonceCannotAuthenticateOrGrantAnUnauthorizedServiceCaller() throws Exception {
        mvc.perform(post(EVALUATION_PATH).header("X-ZeroTrust-Risk-Request", UUID.randomUUID().toString())
                .contentType(MediaType.APPLICATION_JSON).content(BODY)).andExpect(status().isUnauthorized());
        mvc.perform(post(EVALUATION_PATH).header("Authorization", "Bearer " + sign(claims().claim("azp", "zerotrust-spa"), KEY))
                .header("X-ZeroTrust-Risk-Request", UUID.randomUUID().toString())
                .contentType(MediaType.APPLICATION_JSON).content(BODY)).andExpect(status().isForbidden());
        verifyNoInteractions(service, lifecycle);
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"RS384", "RS512", "PS256", "HS256"})
    void unsupportedSignedAlgorithmsCannotReachRisk(String algorithm) throws Exception {
        SignedJWT token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.parse(algorithm))
                .keyID(KEY.getKeyID()).build(), claims().build());
        if (algorithm.equals("HS256")) token.sign(new com.nimbusds.jose.crypto.MACSigner(new byte[32]));
        else token.sign(new RSASSASigner(KEY));
        mvc.perform(post(EVALUATION_PATH).header("Authorization", "Bearer " + token.serialize())
                .contentType(MediaType.APPLICATION_JSON).content(BODY)).andExpect(status().isUnauthorized());
        verifyNoInteractions(service, lifecycle);
    }

    @Test void callerSuppliedScoreAndDecisionCannotReplaceTheServerEvaluation()throws Exception{
        String injected=BODY.strip().replace("}",",\"riskScore\":0,\"decision\":\"ALLOW\"}");
        mvc.perform(post(EVALUATION_PATH).header("Authorization","Bearer "+sign(claims(),KEY))
                .contentType(MediaType.APPLICATION_JSON).content(injected))
                .andExpect(status().isOk()).andExpect(jsonPath("$.decision").value("DENY"))
                .andExpect(jsonPath("$.riskScore").isEmpty());
        verify(service).evaluate(any(LoginContext.class));
    }

    private ResultActions callAuthenticationFailure(String token) throws Exception {
        return mvc.perform(post(AUTHENTICATION_FAILURE_PATH)
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(AUTHENTICATION_FAILURE_BODY));
    }

    @Test void forgedForwardingDoesNotReplaceAuthenticatedCallerIpForNetworkOrHistory() throws Exception {
        String forwarded="10.0.0.1, 127.0.0.1";
        mvc.perform(post(EVALUATION_PATH).header("Authorization","Bearer "+sign(claims(),KEY))
                .header("X-Forwarded-For",forwarded).header("Forwarded","for=10.0.0.1")
                .header("X-Real-IP","10.0.0.1").contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isOk()).andExpect(jsonPath("$.decision").value("DENY"));
        var captured=org.mockito.ArgumentCaptor.forClass(LoginContext.class);
        verify(service).evaluate(captured.capture());
        org.junit.jupiter.api.Assertions.assertEquals("203.0.113.10",captured.getValue().ipAddress());
        mvc.perform(post(AUTHENTICATION_FAILURE_PATH).header("Authorization","Bearer "+sign(
                        claimsWithRoles(RiskJwtAuthenticationConverter.EVENTS_WRITE_AUTHORITY),KEY))
                .header("X-Forwarded-For",forwarded).header("Forwarded","for=10.0.0.1").header("X-Real-IP","10.0.0.1")
                .contentType(MediaType.APPLICATION_JSON).content(AUTHENTICATION_FAILURE_BODY))
                .andExpect(status().isNoContent());
        verify(authenticationFailureService).recordFailure("event-1","student-1","203.0.113.10");
    }

    @Test void forwardingCannotAuthenticateADirectInternalRequest() throws Exception {
        mvc.perform(post(EVALUATION_PATH).header("X-Forwarded-For","127.0.0.1").header("Forwarded","for=127.0.0.1")
                .header("X-Role","risk:evaluate").header("X-Subject","service-account-id")
                .contentType(MediaType.APPLICATION_JSON).content(BODY)).andExpect(status().isUnauthorized());
        verifyNoInteractions(service,lifecycle);
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

    static java.util.stream.Stream<org.junit.jupiter.params.provider.Arguments> serviceMatrix(){
        var cases=new java.util.ArrayList<org.junit.jupiter.params.provider.Arguments>();
        for(int endpoint=0;endpoint<6;endpoint++)for(String caller:List.of("zerotrust-risk-caller","zerotrust-portal-risk-admin","zerotrust-provisioner","zerotrust-spa","application-admin"))
            for(String role:List.of("risk:evaluate","risk:device:write","risk:events:write","risk:device:revoke",""))cases.add(org.junit.jupiter.params.provider.Arguments.of(endpoint,caller,role));
        return cases.stream();
    }
    static String matrixPath(int endpoint){return switch(endpoint){
        case 0->EVALUATION_PATH;case 1->TRUSTED_DEVICE_PATH;case 2->AUTHENTICATION_FAILURE_PATH;case 3->AUTHENTICATION_SUCCESS_PATH;
        default->"/internal/v1/subjects/11111111-1111-4111-8111-111111111111/trusted-devices/revocations"+(endpoint==5?"/completion":"");};}
    static String matrixBody(int endpoint){return switch(endpoint){
        case 0->BODY;case 1->TRUSTED_DEVICE_BODY;case 2->AUTHENTICATION_FAILURE_BODY;case 3->AUTHENTICATION_SUCCESS_BODY;
        default->"{\"operationId\":\"22222222-2222-4222-8222-222222222222\",\"requestedBy\":\"synthetic-admin\"}";};}
    @org.junit.jupiter.params.ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("serviceMatrix")
    void signedCallerAndRoleMatrixDoesNotGrantCrossServiceAuthority(int endpoint,String caller,String role)throws Exception{
        String expectedRole=List.of("risk:evaluate","risk:device:write","risk:events:write","risk:events:write","risk:device:revoke","risk:device:revoke").get(endpoint);
        boolean allowed=caller.equals(endpoint>=4?"zerotrust-portal-risk-admin":"zerotrust-risk-caller") && role.equals(expectedRole);
        String token=sign(claimsWithRoles(role).claim("azp",caller).claim("realm_access",Map.of("roles",List.of("ADMIN"))),KEY);
        mvc.perform(post(matrixPath(endpoint)).header("Authorization","Bearer "+token).header("X-Role",expectedRole)
                .contentType(MediaType.APPLICATION_JSON).content(matrixBody(endpoint)))
                .andExpect(status().is(allowed?(endpoint==0?200:204):403));
        if(!allowed)verifyNoInteractions(service,lifecycle,registrationService,authenticationFailureService,authenticationSuccessService);
    }
    @org.junit.jupiter.params.ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(ints={0,1,2,3,4,5})
    void wrongIssuerAudienceOrExpiryCannotAuthenticateAnyServiceEndpoint(int endpoint)throws Exception{
        for(String invalid:List.of("issuer","audience","expiry")){
            var claims=claimsWithRoles("risk:evaluate","risk:device:write","risk:events:write","risk:device:revoke")
                    .claim("azp",endpoint>=4?"zerotrust-portal-risk-admin":"zerotrust-risk-caller");
            if(invalid.equals("issuer"))claims.issuer("https://wrong.invalid");
            else if(invalid.equals("audience"))claims.audience("zerotrust-api");else claims.expirationTime(null);
            mvc.perform(post(matrixPath(endpoint)).header("Authorization","Bearer "+sign(claims,KEY))
                    .contentType(MediaType.APPLICATION_JSON).content(matrixBody(endpoint))).andExpect(status().isUnauthorized());
        }
        verifyNoInteractions(service,lifecycle,registrationService,authenticationFailureService,authenticationSuccessService);
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
