package com.zerotrust.risk.feature;

import com.zerotrust.risk.config.DeviceRiskProperties;
import com.zerotrust.risk.domain.AuthenticationHistoryRiskAssessment;
import com.zerotrust.risk.domain.DeviceRecognition;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.NetworkRiskAssessment;
import com.zerotrust.risk.domain.NetworkRiskStatus;
import com.zerotrust.risk.domain.RiskDataStatus;
import com.zerotrust.risk.domain.RiskFactors;
import com.zerotrust.risk.domain.RiskFeatureExtraction;
import com.zerotrust.risk.domain.RiskReason;
import com.zerotrust.risk.domain.TemporalProfileStatus;
import com.zerotrust.risk.domain.TemporalRiskAssessment;
import com.zerotrust.risk.service.AuthenticationHistoryRiskCalculator;
import com.zerotrust.risk.service.DeviceRecognitionService;
import com.zerotrust.risk.service.NetworkRiskCalculator;
import com.zerotrust.risk.service.TemporalRiskCalculator;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class DatabaseBackedRiskFeatureExtractor implements RiskFeatureExtractor {

    private final DeviceRecognitionService deviceRecognitionService;
    private final DeviceRiskProperties deviceRiskProperties;
    private final AuthenticationHistoryRiskCalculator authenticationHistoryRiskCalculator;
    private final TemporalRiskCalculator temporalRiskCalculator;
    private final NetworkRiskCalculator networkRiskCalculator;

    @Override
    public RiskFeatureExtraction extract(LoginContext context) {
        DeviceRecognition device = deviceRecognitionService.recognize(context);
        List<RiskReason> reasons = new ArrayList<>();
        Optional<RiskReason> priorityViolation = Optional.empty();
        Optional<RiskReason> mandatoryStepUpReason = Optional.empty();
        BigDecimal deviceRisk;

        switch (device.status()) {
            case MISSING -> {
                deviceRisk = deviceRiskProperties.getMissing();
                reasons.add(RiskReason.DEVICE_IDENTIFIER_MISSING);
            }
            case NEW -> {
                deviceRisk = deviceRiskProperties.getNewDevice();
                reasons.add(RiskReason.NEW_DEVICE);
            }
            case PENDING -> {
                deviceRisk = deviceRiskProperties.getPending();
                reasons.add(RiskReason.PENDING_DEVICE);
            }
            case TRUSTED -> deviceRisk = deviceRiskProperties.getTrusted();
            case REVOKED -> {
                deviceRisk = deviceRiskProperties.getRevoked();
                reasons.add(RiskReason.REVOKED_DEVICE);
                priorityViolation = Optional.of(RiskReason.REVOKED_DEVICE);
            }
            default -> throw new IllegalStateException("Unsupported device recognition status");
        }

        Optional<AuthenticationHistoryRiskAssessment> authenticationHistoryAssessment =
                authenticationHistoryRiskCalculator.calculate(context);
        if (authenticationHistoryAssessment.isEmpty()) {
            reasons.add(RiskReason.AUTHENTICATION_HISTORY_UNAVAILABLE);
        } else {
            AuthenticationHistoryRiskAssessment assessment =
                    authenticationHistoryAssessment.orElseThrow();
            if (assessment.riskScore().compareTo(BigDecimal.ZERO) > 0) {
                reasons.add(RiskReason.AUTHENTICATION_HISTORY_RISK);
            }
            if (assessment.highRisk()) {
                reasons.add(RiskReason.EXCESSIVE_AUTHENTICATION_FAILURES);
                mandatoryStepUpReason = Optional.of(
                        RiskReason.EXCESSIVE_AUTHENTICATION_FAILURES
                );
            }
        }

        NetworkRiskAssessment networkAssessment = networkRiskCalculator.calculate(context);
        BigDecimal networkRisk = BigDecimal.ZERO;
        if (networkAssessment.status() == NetworkRiskStatus.AVAILABLE) {
            networkRisk = networkAssessment.riskScore();
            if (networkRisk.compareTo(BigDecimal.ZERO) > 0) {
                reasons.add(RiskReason.NETWORK_RISK);
            }
        } else {
            reasons.add(RiskReason.NETWORK_INTELLIGENCE_UNAVAILABLE);
        }

        TemporalRiskAssessment temporalAssessment = temporalRiskCalculator.calculate(context);
        BigDecimal temporalRisk = BigDecimal.ZERO;
        if (temporalAssessment.status() == TemporalProfileStatus.AVAILABLE) {
            temporalRisk = temporalAssessment.riskScore();
            if (temporalRisk.compareTo(BigDecimal.ZERO) > 0) {
                reasons.add(RiskReason.TEMPORAL_RISK);
            }
        } else if (temporalAssessment.status() == TemporalProfileStatus.COLD_START) {
            reasons.add(RiskReason.TEMPORAL_PROFILE_COLD_START);
        } else {
            reasons.add(RiskReason.TEMPORAL_PROFILE_UNAVAILABLE);
        }

        boolean complete = authenticationHistoryAssessment.isPresent()
                && networkAssessment.status() == NetworkRiskStatus.AVAILABLE
                && temporalAssessment.status() == TemporalProfileStatus.AVAILABLE;

        return new RiskFeatureExtraction(
                new RiskFactors(
                        deviceRisk,
                        networkRisk,
                        temporalRisk,
                        authenticationHistoryAssessment
                                .map(AuthenticationHistoryRiskAssessment::riskScore)
                                .orElse(BigDecimal.ZERO)
                ),
                complete ? RiskDataStatus.COMPLETE : RiskDataStatus.INCOMPLETE,
                reasons,
                priorityViolation,
                mandatoryStepUpReason
        );
    }
}
