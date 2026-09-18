package com.zerotrust.keycloak.risk.authenticator;

import com.zerotrust.keycloak.risk.client.ClientCredentialsTokenProvider;
import com.zerotrust.keycloak.risk.client.HttpRiskScoringClient;
import com.zerotrust.keycloak.risk.client.ServiceTokenCache;
import com.zerotrust.keycloak.risk.client.TrustedDeviceClientFactory;
import com.zerotrust.keycloak.risk.config.RiskAuthenticatorConfigResolver;
import com.zerotrust.keycloak.risk.context.CookieDeviceIdResolver;
import com.zerotrust.keycloak.risk.context.KeycloakDeviceCookieWriter;
import com.zerotrust.keycloak.risk.context.SecureRandomDeviceIdGenerator;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public final class TrustedDeviceRegistrationAuthenticatorFactory
        implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "zerotrust-device-registration";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    private final ServiceTokenCache tokenCache = new ServiceTokenCache();

    @Override
    public Authenticator create(KeycloakSession session) {
        HttpClientProvider httpClientProvider = session.getProvider(HttpClientProvider.class);
        TrustedDeviceClientFactory clientFactory = config -> {
            var tokenProvider = new ClientCredentialsTokenProvider(
                    httpClientProvider,
                    config.serviceTokenConfig(),
                    config.clientConfig(),
                    tokenCache
            );
            return new HttpRiskScoringClient(
                    httpClientProvider,
                    config.clientConfig(),
                    tokenProvider
            );
        };

        return new TrustedDeviceRegistrationAuthenticator(
                new CookieDeviceIdResolver(),
                new SecureRandomDeviceIdGenerator(),
                new KeycloakDeviceCookieWriter(),
                new RiskAuthenticatorConfigResolver(),
                clientFactory
        );
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "ZeroTrust Remember Device after MFA";
    }

    @Override
    public String getReferenceCategory() {
        return null;
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
        return "Registers and issues the trusted-device cookie after risk-triggered MFA succeeds.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    @Override
    public void init(Config.Scope config) {
        // This provider reuses the evaluator execution configuration by auth-note reference.
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No global resources are created by this factory.
    }

    @Override
    public void close() {
        tokenCache.clear();
    }
}
