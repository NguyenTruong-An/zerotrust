package com.zerotrust.risk.feature;

import com.zerotrust.risk.config.DeviceRiskProperties;
import com.zerotrust.risk.domain.DeviceRecognition;
import com.zerotrust.risk.domain.DeviceRecognitionStatus;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.RiskDataStatus;
import com.zerotrust.risk.domain.RiskFeatureExtraction;
import com.zerotrust.risk.domain.RiskReason;
import com.zerotrust.risk.service.DeviceRecognitionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DatabaseBackedRiskFeatureExtractorTests {

    private static final String HASH = "c".repeat(64);

    @Mock
    private DeviceRecognitionService deviceRecognitionService;

    private DatabaseBackedRiskFeatureExtractor extractor;
    private LoginContext context;

    @BeforeEach
    void setUp() {
        DeviceRiskProperties properties = new DeviceRiskProperties();
        properties.setMissing(new BigDecimal("80"));
        properties.setNewDevice(new BigDecimal("60"));
        properties.setPending(new BigDecimal("50"));
        properties.setTrusted(BigDecimal.ZERO);
        properties.setRevoked(new BigDecimal("100"));

        extractor = new DatabaseBackedRiskFeatureExtractor(
                deviceRecognitionService,
                properties
        );
        context = new LoginContext(
                "subject-1",
                "authentication-session-id",
                "zerotrust-spa",
                "203.0.113.10",
                "Mozilla/5.0",
                "device-1",
                Instant.parse("2026-09-07T01:00:00Z")
        );
    }

    @Test
    void extractsNewDeviceRiskFromDatabaseLookup() {
        when(deviceRecognitionService.recognize(context))
                .thenReturn(new DeviceRecognition(DeviceRecognitionStatus.NEW, HASH));

        RiskFeatureExtraction result = extractor.extract(context);

        assertThat(result.factors().deviceRisk()).isEqualByComparingTo("60");
        assertThat(result.dataStatus()).isEqualTo(RiskDataStatus.INCOMPLETE);
        assertThat(result.reasons()).contains(RiskReason.NEW_DEVICE);
        assertThat(result.priorityViolation()).isEmpty();
    }

    @Test
    void trustedDeviceHasNoDeviceRiskReason() {
        when(deviceRecognitionService.recognize(context))
                .thenReturn(new DeviceRecognition(DeviceRecognitionStatus.TRUSTED, HASH));

        RiskFeatureExtraction result = extractor.extract(context);

        assertThat(result.factors().deviceRisk()).isEqualByComparingTo(BigDecimal.ZERO);
        assertThat(result.reasons()).doesNotContain(
                RiskReason.NEW_DEVICE,
                RiskReason.PENDING_DEVICE,
                RiskReason.REVOKED_DEVICE,
                RiskReason.DEVICE_IDENTIFIER_MISSING
        );
    }

    @Test
    void revokedDeviceCreatesPriorityViolation() {
        when(deviceRecognitionService.recognize(context))
                .thenReturn(new DeviceRecognition(DeviceRecognitionStatus.REVOKED, HASH));

        RiskFeatureExtraction result = extractor.extract(context);

        assertThat(result.factors().deviceRisk()).isEqualByComparingTo("100");
        assertThat(result.priorityViolation()).contains(RiskReason.REVOKED_DEVICE);
    }
}
