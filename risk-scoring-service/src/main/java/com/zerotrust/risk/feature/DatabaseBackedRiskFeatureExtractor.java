package com.zerotrust.risk.feature;

import com.zerotrust.risk.config.DeviceRiskProperties;
import com.zerotrust.risk.domain.DeviceRecognition;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.RiskDataStatus;
import com.zerotrust.risk.domain.RiskFactors;
import com.zerotrust.risk.domain.RiskFeatureExtraction;
import com.zerotrust.risk.domain.RiskReason;
import com.zerotrust.risk.service.DeviceRecognitionService;
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

    @Override
    public RiskFeatureExtraction extract(LoginContext context) {
        DeviceRecognition device = deviceRecognitionService.recognize(context);
        List<RiskReason> reasons = new ArrayList<>();
        Optional<RiskReason> priorityViolation = Optional.empty();
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

        reasons.add(RiskReason.NETWORK_INTELLIGENCE_UNAVAILABLE);
        reasons.add(RiskReason.TEMPORAL_PROFILE_UNAVAILABLE);
        reasons.add(RiskReason.AUTHENTICATION_HISTORY_UNAVAILABLE);

        return new RiskFeatureExtraction(
                new RiskFactors(
                        deviceRisk,
                        BigDecimal.ZERO,
                        BigDecimal.ZERO,
                        BigDecimal.ZERO
                ),
                RiskDataStatus.INCOMPLETE,
                reasons,
                priorityViolation
        );
    }
}
