package com.zerotrust.keycloak.risk.config;

import com.zerotrust.keycloak.risk.authenticator.RiskAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;

import java.util.Comparator;
import java.util.HashSet;
import java.util.Set;

public final class BrowserFlowRiskConfigLocator {

    public AuthenticatorConfigModel locate(RealmModel realm) {
        if (realm == null) {
            throw new RiskAuthenticatorConfigurationException("Event realm was not found");
        }
        AuthenticationFlowModel browserFlow = realm.getBrowserFlow();
        if (browserFlow == null || browserFlow.getId() == null) {
            throw new RiskAuthenticatorConfigurationException(
                    "Realm browser flow is not configured"
            );
        }

        AuthenticatorConfigModel config = find(realm, browserFlow.getId(), new HashSet<>());
        if (config == null) {
            throw new RiskAuthenticatorConfigurationException(
                    "ZeroTrust Risk Evaluation configuration was not found in the browser flow"
            );
        }
        return config;
    }

    private AuthenticatorConfigModel find(
            RealmModel realm,
            String flowId,
            Set<String> visitedFlowIds
    ) {
        if (flowId == null || !visitedFlowIds.add(flowId)) {
            return null;
        }

        for (AuthenticationExecutionModel execution : realm
                .getAuthenticationExecutionsStream(flowId)
                .sorted(Comparator.comparingInt(AuthenticationExecutionModel::getPriority))
                .toList()) {
            if (execution.isAuthenticatorFlow()) {
                AuthenticatorConfigModel nested = find(
                        realm,
                        execution.getFlowId(),
                        visitedFlowIds
                );
                if (nested != null) {
                    return nested;
                }
                continue;
            }
            if (!RiskAuthenticatorFactory.PROVIDER_ID.equals(execution.getAuthenticator())) {
                continue;
            }
            String configId = execution.getAuthenticatorConfig();
            if (configId == null || configId.isBlank()) {
                continue;
            }
            AuthenticatorConfigModel config = realm.getAuthenticatorConfigById(configId);
            if (config != null) {
                return config;
            }
        }
        return null;
    }
}
