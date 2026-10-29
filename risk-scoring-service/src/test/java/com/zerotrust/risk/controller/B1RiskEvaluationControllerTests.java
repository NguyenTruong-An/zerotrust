package com.zerotrust.risk.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.risk.domain.*;
import com.zerotrust.risk.repository.AuthenticationFailureStore;
import com.zerotrust.risk.repository.AuthenticationSuccessEventRepository;
import com.zerotrust.risk.service.DeviceRecognitionService;
import com.zerotrust.risk.service.DeviceTrustLifecycle;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** H2/test-profile + MockMvc, real B1 calculators. I/O sources are mocked; no live service is called.
 * SecurityContext injection only tests the HTTP contract, never Browser/JWT signature acceptance.
 */
@SpringBootTest(properties = {
        "risk.policy.model=CONTINUOUS_B1", "risk.policy.network-risk.enabled=true",
        "risk.policy.network-risk.trusted-cidrs=10.0.0.0/8",
        "risk.policy.network-risk.elevated-risk-cidrs=198.51.100.0/24",
        "risk.policy.network-risk.high-risk-cidrs=203.0.113.0/24", "risk.policy.network-risk.geoip.enabled=false"
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class B1RiskEvaluationControllerTests {
    @Autowired MockMvc mvc;
    @MockitoBean AuthenticationFailureStore failureStore;
    @MockitoBean AuthenticationSuccessEventRepository successRepository;
    @MockitoBean DeviceRecognitionService recognition;
    @MockitoBean DeviceTrustLifecycle lifecycle;

    @BeforeEach
    void contextSources() {
        when(lifecycle.snapshot(anyString())).thenReturn(new DeviceTrustLifecycle.Snapshot(0, false));
        when(recognition.recognize(any())).thenReturn(new DeviceRecognition(DeviceRecognitionStatus.TRUSTED, "synthetic-hmac"));
        Instant now = Instant.now();
        List<Instant> unusual = new ArrayList<>();
        for (int i = 0; i < 6; i++) unusual.add(now.minusSeconds(7L * (i + 1) * 86400).plusSeconds(30 * 3600));
        when(successRepository.findRecentAuthenticationTimes(anyString(), anyString(), any(), any(), any())).thenReturn(unusual);
    }

    @Test
    void b1IsSelectedBySpringAndReturnsFractionalScoreWithoutChangingResponseContract() throws Exception {
        when(failureStore.countBySubject(anyString())).thenReturn(2L);
        String response = request("198.51.100.17").andExpect(jsonPath("$.riskScore").value(45.83))
                .andExpect(jsonPath("$.riskLevel").value("MEDIUM"))
                .andExpect(jsonPath("$.decision").value("STEP_UP_MFA"))
                .andExpect(jsonPath("$.dataStatus").value("COMPLETE"))
                .andReturn().getResponse().getContentAsString();
        // B0 on the same inputs would be37.50/ALLOW; this distinguishes actual bean wiring.
        var row = new ObjectMapper().readTree(response);
        Set<String> fields = new HashSet<>(); row.fieldNames().forEachRemaining(fields::add);
        assertThat(fields).containsExactlyInAnyOrder("evaluationId", "subjectId", "authenticationSessionId",
                "riskScore", "riskLevel", "decision", "dataStatus", "reasons", "evaluatedAt", "trustGeneration");
    }

    @Test
    void b1HttpNumericHighIsCompleteAndNotPriorityDeny() throws Exception {
        when(failureStore.countBySubject(anyString())).thenReturn(5L);
        request("203.0.113.17").andExpect(jsonPath("$.riskScore").value(75.0))
                .andExpect(jsonPath("$.riskLevel").value("HIGH"))
                .andExpect(jsonPath("$.decision").value("DENY"))
                .andExpect(jsonPath("$.dataStatus").value("COMPLETE"));
    }

    @Test
    void b1TemporalNormalizationIsAlsoWiredBySpring() throws Exception {
        Instant now = Instant.now();
        List<Instant> events = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            Instant t = now.minusSeconds(7L * (i / 4 + 1) * 86400);
            if (i >= 2) t = t.plusSeconds(86400);
            if (i >= 3) t = t.plusSeconds(6 * 3600);
            events.add(t);
        }
        when(successRepository.findRecentAuthenticationTimes(anyString(), anyString(), any(), any(), any())).thenReturn(events);
        // T1=12.5, H1=0, N=50 ->15.625 ->15.63. B0's T=50 would give25.00.
        request("198.51.100.17").andExpect(jsonPath("$.riskScore").value(15.63))
                .andExpect(jsonPath("$.decision").value("ALLOW"))
                .andExpect(jsonPath("$.dataStatus").value("COMPLETE"));
    }

    @Test
    void b1ColdStartStillReturnsNullAndRequiresMfa() throws Exception {
        when(successRepository.findRecentAuthenticationTimes(anyString(), anyString(), any(), any(), any())).thenReturn(List.of());
        request("10.1.2.3").andExpect(jsonPath("$.riskScore").doesNotExist())
                .andExpect(jsonPath("$.decision").value("STEP_UP_MFA"))
                .andExpect(jsonPath("$.dataStatus").value("INCOMPLETE"));
    }

    @Test
    void b1PendingResetRemainsPriorityAndDoesNotComputeScore() throws Exception {
        when(lifecycle.snapshot(anyString())).thenReturn(new DeviceTrustLifecycle.Snapshot(1, true));
        request("10.1.2.3").andExpect(jsonPath("$.riskScore").doesNotExist())
                .andExpect(jsonPath("$.decision").value("DENY"))
                .andExpect(jsonPath("$.dataStatus").value("NOT_EVALUATED"))
                .andExpect(jsonPath("$.reasons[0]").value("MFA_RESET_IN_PROGRESS"));
    }

    private org.springframework.test.web.servlet.ResultActions request(String address) throws Exception {
        return mvc.perform(post("/internal/v1/risk/evaluations")
                .with(jwt().jwt(j -> j.claim("azp", "zerotrust-risk-caller"))
                        .authorities(new SimpleGrantedAuthority("risk:evaluate")))
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"subjectId":"synthetic-b1-subject","authenticationSessionId":"synthetic-session",
                         "clientId":"zerotrust-spa","ipAddress":"%s","deviceId":"synthetic-device"}
                        """.formatted(address))).andExpect(status().isOk());
    }
}
