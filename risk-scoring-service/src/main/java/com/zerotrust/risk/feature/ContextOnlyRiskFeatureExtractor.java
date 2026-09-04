package com.zerotrust.risk.feature;

import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.RiskDataStatus;
import com.zerotrust.risk.domain.RiskFactors;
import com.zerotrust.risk.domain.RiskFeatureExtraction;
import com.zerotrust.risk.domain.RiskReason;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

@Component
public class ContextOnlyRiskFeatureExtractor implements RiskFeatureExtractor {

    @Override
    public RiskFeatureExtraction extract(LoginContext context) {
        List<RiskReason> reasons = new ArrayList<>();
        if (context.deviceId() == null || context.deviceId().isBlank()) {
            reasons.add(RiskReason.DEVICE_IDENTIFIER_MISSING);
        }

        reasons.add(RiskReason.DEVICE_HISTORY_UNAVAILABLE);
        reasons.add(RiskReason.NETWORK_INTELLIGENCE_UNAVAILABLE);
        reasons.add(RiskReason.TEMPORAL_PROFILE_UNAVAILABLE);
        reasons.add(RiskReason.AUTHENTICATION_HISTORY_UNAVAILABLE);

        return new RiskFeatureExtraction(
                new RiskFactors(
                        BigDecimal.ZERO,
                        BigDecimal.ZERO,
                        BigDecimal.ZERO,
                        BigDecimal.ZERO
                ),
                RiskDataStatus.INCOMPLETE,
                reasons
        );
    }
}
