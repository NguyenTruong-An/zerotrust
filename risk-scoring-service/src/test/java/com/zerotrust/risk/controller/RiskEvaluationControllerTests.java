package com.zerotrust.risk.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class RiskEvaluationControllerTests {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void evaluatesValidRequest() throws Exception {
        mockMvc.perform(post("/internal/v1/risk/evaluations")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "subjectId": "keycloak-user-id",
                                  "authenticationSessionId": "authentication-session-id",
                                  "clientId": "zerotrust-spa",
                                  "ipAddress": "203.0.113.10",
                                  "userAgent": "Mozilla/5.0",
                                  "deviceId": "device-123"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.riskScore").doesNotExist())
                .andExpect(jsonPath("$.riskLevel").value("MEDIUM"))
                .andExpect(jsonPath("$.decision").value("STEP_UP_MFA"))
                .andExpect(jsonPath("$.dataStatus").value("INCOMPLETE"))
                .andExpect(jsonPath("$.reasons").isArray());
    }

    @Test
    void rejectsInvalidRequest() throws Exception {
        mockMvc.perform(post("/internal/v1/risk/evaluations")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "subjectId": "",
                                  "authenticationSessionId": "authentication-session-id",
                                  "clientId": "zerotrust-spa",
                                  "ipAddress": "999.1.1.1",
                                  "userAgent": "Mozilla/5.0"
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation failed"))
                .andExpect(jsonPath("$['fieldErrors']['subjectId']").exists())
                .andExpect(jsonPath("$['fieldErrors']['ipAddress']").exists());
    }
}
