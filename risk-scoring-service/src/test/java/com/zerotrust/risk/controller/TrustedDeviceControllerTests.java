package com.zerotrust.risk.controller;

import com.zerotrust.risk.entity.DeviceStatus;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class TrustedDeviceControllerTests {

    private static final String PATH = "/internal/v1/trusted-devices";
    private static final String SUBJECT_ID = "keycloak-user-id";
    private static final String DEVICE_ID = "secure-random-device-identifier";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private KnownDeviceRepository repository;

    @Autowired
    private DeviceFingerprintHasher fingerprintHasher;

    @Test
    void registersTrustedDeviceAndReturnsNoContent() throws Exception {
        mockMvc.perform(post(PATH)
                        .with(deviceWriteAuthentication())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validBody()))
                .andExpect(status().isNoContent())
                .andExpect(header().doesNotExist("Set-Cookie"));

        String fingerprintHash = fingerprintHasher.hash(SUBJECT_ID, DEVICE_ID);
        KnownDeviceEntity stored = repository
                .findBySubjectIdAndDeviceFingerprintHash(SUBJECT_ID, fingerprintHash)
                .orElseThrow();
        assertThat(stored.getStatus()).isEqualTo(DeviceStatus.TRUSTED);
        assertThat(stored.getDeviceFingerprintHash()).doesNotContain(DEVICE_ID);
    }

    @Test
    void rejectsInvalidRegistrationRequest() throws Exception {
        mockMvc.perform(post(PATH)
                        .with(deviceWriteAuthentication())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"subjectId":"", "deviceId":""}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation failed"))
                .andExpect(jsonPath("$['fieldErrors']['subjectId']").exists())
                .andExpect(jsonPath("$['fieldErrors']['deviceId']").exists());

        assertThat(repository.count()).isZero();
    }

    @Test
    void reportsConflictWhenDeviceWasRevoked() throws Exception {
        String fingerprintHash = fingerprintHasher.hash(SUBJECT_ID, DEVICE_ID);
        Instant firstSeenAt = Instant.now().minusSeconds(120);
        KnownDeviceEntity device = new KnownDeviceEntity(SUBJECT_ID, fingerprintHash, firstSeenAt);
        device.revoke(firstSeenAt.plusSeconds(60));
        repository.saveAndFlush(device);

        mockMvc.perform(post(PATH)
                        .with(deviceWriteAuthentication())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validBody()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("DEVICE_TRUST_REJECTED"))
                .andExpect(jsonPath("$.path").value(PATH));

        assertThat(device.getStatus()).isEqualTo(DeviceStatus.REVOKED);
    }

    private static String validBody() {
        return """
                {
                  "subjectId": "keycloak-user-id",
                  "deviceId": "secure-random-device-identifier"
                }
                """;
    }

    private static RequestPostProcessor deviceWriteAuthentication() {
        Jwt jwt = Jwt.withTokenValue("test")
                .header("alg", "RS256")
                .subject("service-account-id")
                .claim("azp", "zerotrust-risk-caller")
                .claim("resource_access", Map.of(
                        "zerotrust-risk-api",
                        Map.of("roles", List.of(
                                RiskJwtAuthenticationConverter.DEVICE_WRITE_AUTHORITY
                        ))
                ))
                .build();
        return authentication(new RiskJwtAuthenticationConverter("zerotrust-risk-api").convert(jwt));
    }
}
