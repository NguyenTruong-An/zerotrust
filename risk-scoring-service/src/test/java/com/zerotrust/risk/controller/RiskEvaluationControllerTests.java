package com.zerotrust.risk.controller;

import com.zerotrust.risk.entity.KnownDeviceEntity;
import com.zerotrust.risk.repository.KnownDeviceRepository;
import com.zerotrust.risk.security.RiskJwtAuthenticationConverter;
import com.zerotrust.risk.service.DeviceFingerprintHasher;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class RiskEvaluationControllerTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private KnownDeviceRepository knownDeviceRepository;

    @Autowired
    private DeviceFingerprintHasher deviceFingerprintHasher;

    @Test
    void evaluatesValidRequest() throws Exception {
        mockMvc.perform(post("/internal/v1/risk/evaluations")
                        .with(serviceAuthentication())
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
                .andExpect(jsonPath("$.reasons[0]").value("NEW_DEVICE"));
    }

    @Test
    void rejectsInvalidRequest() throws Exception {
        mockMvc.perform(post("/internal/v1/risk/evaluations")
                        .with(serviceAuthentication())
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

    @Test
    void deniesRevokedDeviceFromDatabase() throws Exception {
        String subjectId = "revoked-device-user";
        String deviceId = "revoked-device-id";
        String fingerprintHash = deviceFingerprintHasher.hash(subjectId, deviceId);
        Instant firstSeenAt = Instant.parse("2026-09-07T01:00:00Z");
        KnownDeviceEntity device = new KnownDeviceEntity(
                subjectId,
                fingerprintHash,
                firstSeenAt
        );
        device.revoke(firstSeenAt.plusSeconds(60));
        knownDeviceRepository.saveAndFlush(device);

        mockMvc.perform(post("/internal/v1/risk/evaluations")
                        .with(serviceAuthentication())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "subjectId": "revoked-device-user",
                                  "authenticationSessionId": "revoked-device-session",
                                  "clientId": "zerotrust-spa",
                                  "ipAddress": "203.0.113.20",
                                  "userAgent": "Mozilla/5.0",
                                  "deviceId": "revoked-device-id"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.riskScore").doesNotExist())
                .andExpect(jsonPath("$.riskLevel").value("HIGH"))
                .andExpect(jsonPath("$.decision").value("DENY"))
                .andExpect(jsonPath("$.dataStatus").value("NOT_EVALUATED"))
                .andExpect(jsonPath("$.reasons[0]").value("REVOKED_DEVICE"));
    }
    private static RequestPostProcessor serviceAuthentication() {
        Jwt jwt = Jwt.withTokenValue("test")
                .header("alg", "RS256")
                .subject("service-account-id")
                .claim("azp", "zerotrust-risk-caller")
                .claim("resource_access", Map.of(
                        "zerotrust-risk-api",
                        Map.of("roles", List.of("risk:evaluate"))
                ))
                .build();
        return authentication(new RiskJwtAuthenticationConverter("zerotrust-risk-api").convert(jwt));
    }
}
