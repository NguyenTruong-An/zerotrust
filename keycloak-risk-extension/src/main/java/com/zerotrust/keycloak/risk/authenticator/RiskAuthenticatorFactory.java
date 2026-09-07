package com.zerotrust.keycloak.risk.authenticator;

import com.zerotrust.keycloak.risk.client.HttpRiskScoringClient;
import com.zerotrust.keycloak.risk.client.RiskScoringClientFactory;
import com.zerotrust.keycloak.risk.config.RiskAuthenticatorConfigResolver;
import com.zerotrust.keycloak.risk.config.RiskScoringClientConfig;
import com.zerotrust.keycloak.risk.context.CookieDeviceIdResolver;
import com.zerotrust.keycloak.risk.context.KeycloakLoginContextExtractor;
import com.zerotrust.keycloak.risk.policy.RiskDecisionHandler;
import com.zerotrust.keycloak.risk.policy.RiskFailureMode;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public final class RiskAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "zerotrust-risk-authenticator";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = List.of(
            requiredProperty(
                    RiskAuthenticatorConfigResolver.SERVICE_BASE_URL,
                    "Risk Service base URL",
                    "Base URL of the internal Risk Scoring Service, without the evaluation path.",
                    ProviderConfigProperty.URL_TYPE,
                    null
            ),
            property(
                    RiskAuthenticatorConfigResolver.CONNECTION_REQUEST_TIMEOUT_MS,
                    "Connection pool wait timeout (ms)",
                    "Maximum time to wait for a connection from Keycloak's managed HTTP pool.",
                    ProviderConfigProperty.INTEGER_TYPE,
                    Math.toIntExact(RiskScoringClientConfig.DEFAULT_CONNECTION_REQUEST_TIMEOUT.toMillis())
            ),
            property(
                    RiskAuthenticatorConfigResolver.CONNECT_TIMEOUT_MS,
                    "Connect timeout (ms)",
                    "Maximum time to establish a connection to the Risk Scoring Service.",
                    ProviderConfigProperty.INTEGER_TYPE,
                    Math.toIntExact(RiskScoringClientConfig.DEFAULT_CONNECT_TIMEOUT.toMillis())
            ),
            property(
                    RiskAuthenticatorConfigResolver.SOCKET_TIMEOUT_MS,
                    "Socket timeout (ms)",
                    "Maximum inactivity time while waiting for the Risk Scoring Service response.",
                    ProviderConfigProperty.INTEGER_TYPE,
                    Math.toIntExact(RiskScoringClientConfig.DEFAULT_SOCKET_TIMEOUT.toMillis())
            ),
            property(
                    RiskAuthenticatorConfigResolver.MAX_RESPONSE_BYTES,
                    "Maximum response size (bytes)",
                    "Reject responses larger than this limit.",
                    ProviderConfigProperty.INTEGER_TYPE,
                    RiskScoringClientConfig.DEFAULT_MAX_RESPONSE_BYTES
            ),
            listProperty(
                    RiskAuthenticatorConfigResolver.FAILURE_MODE,
                    "Failure mode",
                    "Action when the Risk Scoring Service is unavailable. DENY is fail-closed.",
                    RiskFailureMode.DENY.name(),
                    List.of(RiskFailureMode.DENY.name(), RiskFailureMode.STEP_UP_MFA.name())
            )
    );

    @Override
    public Authenticator create(KeycloakSession session) {
        HttpClientProvider httpClientProvider = session.getProvider(HttpClientProvider.class);
        RiskScoringClientFactory clientFactory = config -> new HttpRiskScoringClient(
                httpClientProvider,
                config
        );

        return new RiskAuthenticator(
                new KeycloakLoginContextExtractor(new CookieDeviceIdResolver()),
                new RiskAuthenticatorConfigResolver(),
                clientFactory,
                new RiskDecisionHandler()
        );
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "ZeroTrust Risk Evaluation";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
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
        return "Calls the internal Risk Scoring Service and records allow, step-up MFA, or deny.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public void init(Config.Scope config) {
        // Configuration is stored per authentication-flow execution.
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No global resources are created by this factory.
    }

    @Override
    public void close() {
        // Keycloak owns all injected providers.
    }

    private static ProviderConfigProperty property(
            String name,
            String label,
            String helpText,
            String type,
            Object defaultValue
    ) {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(name);
        property.setLabel(label);
        property.setHelpText(helpText);
        property.setType(type);
        property.setDefaultValue(defaultValue);
        return property;
    }

    private static ProviderConfigProperty requiredProperty(
            String name,
            String label,
            String helpText,
            String type,
            Object defaultValue
    ) {
        ProviderConfigProperty property = property(name, label, helpText, type, defaultValue);
        property.setRequired(true);
        return property;
    }

    private static ProviderConfigProperty listProperty(
            String name,
            String label,
            String helpText,
            Object defaultValue,
            List<String> options
    ) {
        ProviderConfigProperty property = property(
                name,
                label,
                helpText,
                ProviderConfigProperty.LIST_TYPE,
                defaultValue
        );
        property.setOptions(options);
        return property;
    }
}
