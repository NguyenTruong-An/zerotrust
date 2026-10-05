package com.zerotrust.risk.controller;

import com.zerotrust.risk.service.DeviceTrustLifecycle;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.util.UUID;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class TrustedDeviceRevocationControllerTests {
    @Autowired MockMvc mvc;
    @Autowired DeviceTrustLifecycle lifecycle;

    @Test
    void requiresDedicatedCallerAndRoleOnBothEndpoints() throws Exception {
        String path = path(UUID.randomUUID());
        String body = body();
        for (String suffix : new String[]{"", "/completion"}) {
            mvc.perform(post(path + suffix).contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isUnauthorized());
            for (String caller : new String[]{"zerotrust-spa", "zerotrust-provisioner", "zerotrust-risk-caller"}) {
                mvc.perform(post(path + suffix).with(auth(caller, "risk:device:revoke"))
                        .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isForbidden());
            }
            mvc.perform(post(path + suffix).with(auth("zerotrust-portal-risk-admin", "risk:device:write"))
                    .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isForbidden());
        }
        mvc.perform(post("/internal/v1/trusted-devices").with(auth("zerotrust-portal-risk-admin", "risk:device:write"))
                .contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isForbidden());
    }

    @Test
    void resetBlocksRiskEvaluationUntilCompletionAndAllowsIdempotentReplay() throws Exception {
        UUID subject = UUID.randomUUID();
        String path = path(subject);
        String body = body();
        for (int i = 0; i < 2; i++) {
            mvc.perform(post(path).with(auth("zerotrust-portal-risk-admin", "risk:device:revoke"))
                    .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isNoContent());
        }
        mvc.perform(post("/internal/v1/risk/evaluations").with(auth("zerotrust-risk-caller", "risk:evaluate"))
                        .contentType(MediaType.APPLICATION_JSON).content("""
                                {"subjectId":"%s","authenticationSessionId":"session-1",
                                 "clientId":"zerotrust-spa","ipAddress":"203.0.113.10"}
                                """.formatted(subject)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.decision").value("DENY"))
                .andExpect(jsonPath("$.reasons[0]").value("MFA_RESET_IN_PROGRESS"))
                .andExpect(jsonPath("$.trustGeneration").value(1));
        mvc.perform(post(path + "/completion").with(auth("zerotrust-portal-risk-admin", "risk:device:revoke"))
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isNoContent());
    }

    @Test
    void registrationWithoutGenerationIsRejected() throws Exception {
        mvc.perform(post("/internal/v1/trusted-devices").with(auth("zerotrust-risk-caller", "risk:device:write"))
                .contentType(MediaType.APPLICATION_JSON).content("{\"subjectId\":\"user\",\"deviceId\":\"device\"}"))
                .andExpect(status().isBadRequest());
    }

    private static String path(UUID subject) { return "/internal/v1/subjects/" + subject + "/trusted-devices/revocations"; }
    private static String body() { return "{\"operationId\":\"" + UUID.randomUUID() + "\",\"requestedBy\":\"admin-1\"}"; }
    private static RequestPostProcessor auth(String caller, String role) {
        return jwt().jwt(token -> token.claim("azp", caller)).authorities(new SimpleGrantedAuthority(role));
    }
}
