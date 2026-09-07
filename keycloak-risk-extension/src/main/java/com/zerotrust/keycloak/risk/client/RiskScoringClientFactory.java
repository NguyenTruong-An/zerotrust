package com.zerotrust.keycloak.risk.client;

import com.zerotrust.keycloak.risk.config.RiskScoringClientConfig;

@FunctionalInterface
public interface RiskScoringClientFactory {

    RiskScoringClient create(RiskScoringClientConfig config);
}
