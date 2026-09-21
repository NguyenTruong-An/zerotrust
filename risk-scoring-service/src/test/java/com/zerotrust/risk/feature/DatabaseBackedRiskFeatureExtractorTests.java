package com.zerotrust.risk.feature;

import com.zerotrust.risk.config.DeviceRiskProperties;
import com.zerotrust.risk.domain.AuthenticationHistoryRiskAssessment;
import com.zerotrust.risk.domain.DeviceRecognition;
import com.zerotrust.risk.domain.DeviceRecognitionStatus;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.NetworkRiskAssessment;
import com.zerotrust.risk.domain.RiskDataStatus;
import com.zerotrust.risk.domain.RiskFeatureExtraction;
import com.zerotrust.risk.domain.RiskReason;
import com.zerotrust.risk.domain.TemporalRiskAssessment;
import com.zerotrust.risk.service.AuthenticationHistoryRiskCalculator;
import com.zerotrust.risk.service.DeviceRecognitionService;
import com.zerotrust.risk.service.NetworkRiskCalculator;
import com.zerotrust.risk.service.TemporalRiskCalculator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DatabaseBackedRiskFeatureExtractorTests {

    private static final String HASH = "c".repeat(64);

    @Mock
    private DeviceRecognitionService deviceRecognitionService;

    @Mock
    private AuthenticationHistoryRiskCalculator authenticationHistoryRiskCalculator;

    @Mock
    private TemporalRiskCalculator temporalRiskCalculator;

    @Mock
    private NetworkRiskCalculator networkRiskCalculator;

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
                properties,
                authenticationHistoryRiskCalculator,
                temporalRiskCalculator,
                networkRiskCalculator
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
        lenient().when(networkRiskCalculator.calculate(context))
                .thenReturn(NetworkRiskAssessment.unavailable());
    }

    @Test
    void extractsNewDeviceRiskFromDatabaseLookup() {
        historyRisk("0");
        temporalRisk("0");
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
        historyRisk("0");
        temporalRisk("0");
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
        historyRisk("0");
        temporalRisk("0");
        when(deviceRecognitionService.recognize(context))
                .thenReturn(new DeviceRecognition(DeviceRecognitionStatus.REVOKED, HASH));

        RiskFeatureExtraction result = extractor.extract(context);

        assertThat(result.factors().deviceRisk()).isEqualByComparingTo("100");
        assertThat(result.priorityViolation()).contains(RiskReason.REVOKED_DEVICE);
    }

    @Test
    void includesAvailableAuthenticationHistoryRisk() {
        historyRisk("100");
        temporalRisk("0");
        when(deviceRecognitionService.recognize(context))
                .thenReturn(new DeviceRecognition(DeviceRecognitionStatus.TRUSTED, HASH));

        RiskFeatureExtraction result = extractor.extract(context);

        assertThat(result.factors().authenticationHistoryRisk()).isEqualByComparingTo("100");
        assertThat(result.reasons()).contains(RiskReason.AUTHENTICATION_HISTORY_RISK);
        assertThat(result.reasons()).doesNotContain(
                RiskReason.AUTHENTICATION_HISTORY_UNAVAILABLE
        );
        assertThat(result.mandatoryStepUpReason())
                .contains(RiskReason.EXCESSIVE_AUTHENTICATION_FAILURES);
    }

    @Test
    void mediumAuthenticationHistoryRiskDoesNotForceStepUpByItself() {
        historyRisk("50");
        temporalRisk("0");
        networkRisk("0");
        when(deviceRecognitionService.recognize(context))
                .thenReturn(new DeviceRecognition(DeviceRecognitionStatus.TRUSTED, HASH));

        RiskFeatureExtraction result = extractor.extract(context);

        assertThat(result.dataStatus()).isEqualTo(RiskDataStatus.COMPLETE);
        assertThat(result.mandatoryStepUpReason()).isEmpty();
    }

    @Test
    void marksAuthenticationHistoryUnavailableWhenRedisCannotBeRead() {
        when(authenticationHistoryRiskCalculator.calculate(context)).thenReturn(Optional.empty());
        temporalRisk("0");
        when(deviceRecognitionService.recognize(context))
                .thenReturn(new DeviceRecognition(DeviceRecognitionStatus.TRUSTED, HASH));

        RiskFeatureExtraction result = extractor.extract(context);

        assertThat(result.factors().authenticationHistoryRisk())
                .isEqualByComparingTo(BigDecimal.ZERO);
        assertThat(result.reasons()).contains(RiskReason.AUTHENTICATION_HISTORY_UNAVAILABLE);
    }

    @Test
    void includesAvailableTemporalRisk() {
        historyRisk("0");
        temporalRisk("50");
        when(deviceRecognitionService.recognize(context))
                .thenReturn(new DeviceRecognition(DeviceRecognitionStatus.TRUSTED, HASH));

        RiskFeatureExtraction result = extractor.extract(context);

        assertThat(result.factors().temporalRisk()).isEqualByComparingTo("50");
        assertThat(result.reasons()).contains(RiskReason.TEMPORAL_RISK);
        assertThat(result.reasons()).doesNotContain(
                RiskReason.TEMPORAL_PROFILE_COLD_START,
                RiskReason.TEMPORAL_PROFILE_UNAVAILABLE
        );
    }

    @Test
    void marksTemporalProfileColdStartWithoutCreatingALowRiskSignal() {
        historyRisk("0");
        when(temporalRiskCalculator.calculate(context))
                .thenReturn(TemporalRiskAssessment.coldStart());
        when(deviceRecognitionService.recognize(context))
                .thenReturn(new DeviceRecognition(DeviceRecognitionStatus.TRUSTED, HASH));

        RiskFeatureExtraction result = extractor.extract(context);

        assertThat(result.factors().temporalRisk()).isEqualByComparingTo(BigDecimal.ZERO);
        assertThat(result.reasons()).contains(RiskReason.TEMPORAL_PROFILE_COLD_START);
        assertThat(result.reasons()).doesNotContain(RiskReason.TEMPORAL_PROFILE_UNAVAILABLE);
    }

    @Test
    void marksTemporalProfileUnavailableWhenDatabaseCannotBeRead() {
        historyRisk("0");
        when(temporalRiskCalculator.calculate(context))
                .thenReturn(TemporalRiskAssessment.unavailable());
        when(deviceRecognitionService.recognize(context))
                .thenReturn(new DeviceRecognition(DeviceRecognitionStatus.TRUSTED, HASH));

        RiskFeatureExtraction result = extractor.extract(context);

        assertThat(result.factors().temporalRisk()).isEqualByComparingTo(BigDecimal.ZERO);
        assertThat(result.reasons()).contains(RiskReason.TEMPORAL_PROFILE_UNAVAILABLE);
        assertThat(result.reasons()).doesNotContain(RiskReason.TEMPORAL_PROFILE_COLD_START);
    }

    @Test
    void returnsCompleteDataWhenEveryRequiredFeatureIsAvailable() {
        historyRisk("0");
        temporalRisk("0");
        networkRisk("0");
        when(deviceRecognitionService.recognize(context))
                .thenReturn(new DeviceRecognition(DeviceRecognitionStatus.TRUSTED, HASH));

        RiskFeatureExtraction result = extractor.extract(context);

        assertThat(result.dataStatus()).isEqualTo(RiskDataStatus.COMPLETE);
        assertThat(result.factors().networkRisk()).isEqualByComparingTo(BigDecimal.ZERO);
        assertThat(result.reasons()).doesNotContain(RiskReason.NETWORK_INTELLIGENCE_UNAVAILABLE);
    }

    @Test
    void includesAvailableNetworkRisk() {
        historyRisk("0");
        temporalRisk("0");
        networkRisk("50");
        when(deviceRecognitionService.recognize(context))
                .thenReturn(new DeviceRecognition(DeviceRecognitionStatus.TRUSTED, HASH));

        RiskFeatureExtraction result = extractor.extract(context);

        assertThat(result.dataStatus()).isEqualTo(RiskDataStatus.COMPLETE);
        assertThat(result.factors().networkRisk()).isEqualByComparingTo("50");
        assertThat(result.reasons()).contains(RiskReason.NETWORK_RISK);
        assertThat(result.reasons()).doesNotContain(RiskReason.NETWORK_INTELLIGENCE_UNAVAILABLE);
    }

    @Test
    void marksNetworkIntelligenceUnavailableWithoutCreatingALowRiskSignal() {
        historyRisk("0");
        temporalRisk("0");
        when(deviceRecognitionService.recognize(context))
                .thenReturn(new DeviceRecognition(DeviceRecognitionStatus.TRUSTED, HASH));

        RiskFeatureExtraction result = extractor.extract(context);

        assertThat(result.dataStatus()).isEqualTo(RiskDataStatus.INCOMPLETE);
        assertThat(result.factors().networkRisk()).isEqualByComparingTo(BigDecimal.ZERO);
        assertThat(result.reasons()).contains(RiskReason.NETWORK_INTELLIGENCE_UNAVAILABLE);
    }

    private void historyRisk(String score) {
        when(authenticationHistoryRiskCalculator.calculate(context))
                .thenReturn(Optional.of(new AuthenticationHistoryRiskAssessment(
                        new BigDecimal(score),
                        new BigDecimal(score).compareTo(new BigDecimal("100")) >= 0
                )));
    }

    private void temporalRisk(String score) {
        when(temporalRiskCalculator.calculate(context))
                .thenReturn(TemporalRiskAssessment.available(new BigDecimal(score)));
    }

    private void networkRisk(String score) {
        when(networkRiskCalculator.calculate(context))
                .thenReturn(NetworkRiskAssessment.available(new BigDecimal(score)));
    }
}
