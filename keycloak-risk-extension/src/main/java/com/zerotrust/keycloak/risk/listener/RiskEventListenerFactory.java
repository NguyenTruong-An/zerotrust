package com.zerotrust.keycloak.risk.listener;

import com.zerotrust.keycloak.risk.client.AuthenticationEventClientFactory;
import com.zerotrust.keycloak.risk.client.ClientCredentialsTokenProvider;
import com.zerotrust.keycloak.risk.client.HttpRiskScoringClient;
import com.zerotrust.keycloak.risk.client.ServiceTokenCache;
import com.zerotrust.keycloak.risk.config.BrowserFlowRiskConfigLocator;
import com.zerotrust.keycloak.risk.config.RiskAuthenticatorConfigResolver;
import com.zerotrust.keycloak.risk.config.RiskEventListenerConfigResolver;
import org.keycloak.Config;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public final class RiskEventListenerFactory implements EventListenerProviderFactory {

    public static final String PROVIDER_ID = "zerotrust-risk-events";

    private final ServiceTokenCache tokenCache = new ServiceTokenCache();

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        HttpClientProvider httpClientProvider = session.getProvider(HttpClientProvider.class);
        AuthenticationEventClientFactory clientFactory = config -> {
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

        return new RiskEventListener(
                session,
                new BrowserFlowRiskConfigLocator(),
                new RiskEventListenerConfigResolver(new RiskAuthenticatorConfigResolver()),
                clientFactory
        );
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(Config.Scope config) {
        // Reuses the configuration of ZeroTrust Risk Evaluation in the browser flow.
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
