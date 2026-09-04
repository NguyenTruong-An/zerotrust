package com.zerotrust.risk.feature;

import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.RiskFeatureExtraction;

public interface RiskFeatureExtractor {

    RiskFeatureExtraction extract(LoginContext context);
}
