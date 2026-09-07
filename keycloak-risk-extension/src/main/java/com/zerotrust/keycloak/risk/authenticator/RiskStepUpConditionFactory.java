package com.zerotrust.keycloak.risk.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public final class RiskStepUpConditionFactory implements ConditionalAuthenticatorFactory {

    public static final String PROVIDER_ID = "zerotrust-risk-step-up-condition";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public ConditionalAuthenticator getSingleton() {
        return RiskStepUpCondition.INSTANCE;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Condition - ZeroTrust step-up required";
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES.clone();
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Runs the conditional MFA subflow when risk evaluation requires step-up.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    @Override
    public void init(Config.Scope config) {
        // No configuration.
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No global resources.
    }

    @Override
    public void close() {
        // Stateless factory.
    }
}
