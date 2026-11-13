package com.zerotrust.risk.networkv2;

import com.zerotrust.risk.domain.GeoIpLocation;
import com.zerotrust.risk.domain.GeoIpLookupResult;
import com.zerotrust.risk.repository.AuthenticationFailureStore;
import com.zerotrust.risk.security.RiskJwtAuthenticationConverter;
import com.zerotrust.risk.service.AuthenticationHistoryKeyHasher;
import com.zerotrust.risk.service.GeoIpProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import tools.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {"risk.network-v2.mode=SHADOW",
        "spring.datasource.url=jdbc:h2:mem:network_v2_flow;MODE=MySQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE"})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class NetworkRiskV2FlowIntegrationTests {
    @MockitoBean AuthenticationFailureStore failureStore;
    @MockitoBean GeoIpProvider geo;
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired NetworkContextRepository history;
    @Autowired AuthenticationHistoryKeyHasher hasher;
    @Autowired JdbcTemplate jdbc;
    @Autowired NetworkRiskV2WorkQueue workQueue;
    private void drain() throws Exception {
        var finished = new java.util.concurrent.CountDownLatch(1);
        assertThat(workQueue.offer(finished::countDown)).isTrue();
        assertThat(finished.await(5, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
    }
    @BeforeEach void geo() {
        when(geo.isEnabled()).thenReturn(true); when(geo.isReady()).thenReturn(true);
        when(geo.lookup("8.8.8.8")).thenReturn(GeoIpLookupResult.available(new GeoIpLocation("US", null, null, 20, 15169L, null)));
    }
    private static RequestPostProcessor service(String caller, String role) {
        Jwt jwt = Jwt.withTokenValue("synthetic-test-only").header("alg", "RS256").subject("service-account")
                .claim("azp", caller).claim("resource_access", Map.of("zerotrust-risk-api", Map.of("roles", List.of(role)))).build();
        return authentication(new RiskJwtAuthenticationConverter("zerotrust-risk-api").convert(jwt));
    }
    private String evaluate(String subject, String expectedDecision) throws Exception {
        String body = json.writeValueAsString(Map.of("subjectId", subject, "authenticationSessionId", "synthetic-session",
                "clientId", "zerotrust-spa", "ipAddress", "8.8.8.8", "deviceId", "synthetic-device"));
        String response = mvc.perform(post("/internal/v1/risk/evaluations")
                        .with(service("zerotrust-risk-caller", "risk:evaluate"))
                        .header("X-Forwarded-For", "1.1.1.1").header("Forwarded", "for=1.1.1.1")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk()).andExpect(jsonPath("$.decision").value(expectedDecision))
                .andExpect(jsonPath("$.networkV2").doesNotExist()).andReturn().getResponse().getContentAsString();
        verify(geo, never()).lookup("1.1.1.1");
        drain();
        return json.readTree(response).get("evaluationId").asText();
    }
    private String successBody(String event, String subject, String evaluation) throws Exception {
        var body = new java.util.LinkedHashMap<String, Object>();
        body.put("eventId", event); body.put("subjectId", subject); body.put("clientId", "zerotrust-spa");
        body.put("authenticatedAt", Instant.now().toString());
        if (evaluation != null) body.put("riskEvaluationId", evaluation);
        return json.writeValueAsString(body);
    }
    private void success(String event, String subject, String evaluation) throws Exception {
        mvc.perform(post("/internal/v1/authentication-successes")
                        .with(service("zerotrust-risk-caller", "risk:events:write"))
                        .contentType(MediaType.APPLICATION_JSON).content(successBody(event, subject, evaluation)))
                .andExpect(status().isNoContent());
        drain();
    }
    @Test void evaluateOnlyDoesNotLearnThenVerifiedSuccessLearnsWithoutChangingMfaDecision() throws Exception {
        String subject = UUID.randomUUID().toString(); String event = UUID.randomUUID().toString();
        String evaluation = evaluate(subject, "STEP_UP_MFA");
        assertThat(history.findAll()).noneMatch(row -> row.getSubjectHash().equals(hasher.hash("network-v2-subject", subject)));
        success(event, subject, evaluation);
        var stored = history.findById(event).orElseThrow();
        assertThat(stored.getSubjectHash()).isEqualTo(hasher.hash("network-v2-subject", subject));
        assertThat(stored.getNetworkHash()).isEqualTo(hasher.hash("network-v2-address", "8.8.8.8"));
        assertThat(stored.getAsn()).isEqualTo(15169);
        success(UUID.randomUUID().toString(), subject, evaluation);
        assertThat(history.findAll().stream().filter(row -> stored.getSubjectHash().equals(row.getSubjectHash())).count()).isEqualTo(1);
    }
    @Test void crossSubjectReplayCannotConsumeAnotherSubjectsEvaluation() throws Exception {
        String owner = UUID.randomUUID().toString(); String other = UUID.randomUUID().toString();
        String evaluation = evaluate(owner, "STEP_UP_MFA");
        String rejectedEvent = UUID.randomUUID().toString();
        success(rejectedEvent, other, evaluation);
        assertThat(history.existsById(rejectedEvent)).isFalse();
        String validEvent = UUID.randomUUID().toString();
        success(validEvent, owner, evaluation);
        assertThat(history.existsById(validEvent)).isTrue();
        // An existing event cannot be reassigned by duplicate delivery.
        success(validEvent, other, evaluate(other, "STEP_UP_MFA"));
        assertThat(history.findById(validEvent).orElseThrow().getSubjectHash()).isEqualTo(hasher.hash("network-v2-subject", owner));
    }
    @Test void oldClientWithoutCorrelationStillWorksButCreatesNoNetworkHistory() throws Exception {
        String event = UUID.randomUUID().toString();
        success(event, UUID.randomUUID().toString(), null);
        assertThat(history.existsById(event)).isFalse();
    }
    @Test void pendingResetDenyAndGenerationAdvancePreventLearning() throws Exception {
        String subject = UUID.randomUUID().toString();
        jdbc.update("INSERT INTO subject_device_trust(subject_id,generation,pending_operation_id) VALUES (?,5,?)", subject, UUID.randomUUID().toString());
        String evaluation = evaluate(subject, "DENY");
        String event = UUID.randomUUID().toString(); success(event, subject, evaluation);
        assertThat(history.existsById(event)).isFalse();
        String other = UUID.randomUUID().toString();
        String beforeReset = evaluate(other, "STEP_UP_MFA");
        jdbc.update("UPDATE subject_device_trust SET generation=generation+1 WHERE subject_id=?", other);
        String staleEvent = UUID.randomUUID().toString(); success(staleEvent, other, beforeReset);
        assertThat(history.existsById(staleEvent)).isFalse();
    }
    @Test void userTokensCannotInjectVerifiedSuccessOrReadAnotherSubjectsNetworkHistory() throws Exception {
        mvc.perform(post("/internal/v1/authentication-successes")
                        .with(service("zerotrust-spa", "risk:events:write"))
                        .contentType(MediaType.APPLICATION_JSON).content(successBody(UUID.randomUUID().toString(), "victim", UUID.randomUUID().toString())))
                .andExpect(status().isForbidden());
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/internal/v1/network-history")
                        .with(service("zerotrust-spa", "ADMIN"))).andExpect(status().isForbidden());
    }
}
