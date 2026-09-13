package com.zerotrust.keycloak.risk.authenticator;

import com.zerotrust.keycloak.risk.config.RiskAuthenticatorConfigResolver;
import org.junit.jupiter.api.Test;
import org.keycloak.provider.ProviderConfigProperty;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProviderRegistrationTest {

    private static final String SERVICE_FILE =
            "META-INF/services/org.keycloak.authentication.AuthenticatorFactory";

    @Test
    void registersBothAuthenticatorFactories() throws IOException {
        Enumeration<URL> resources = Thread.currentThread()
                .getContextClassLoader()
                .getResources(SERVICE_FILE);
        List<String> registrations = new ArrayList<>();
        while (resources.hasMoreElements()) {
            URL resource = resources.nextElement();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    resource.openStream(),
                    StandardCharsets.UTF_8
            ))) {
                registrations.addAll(reader.lines().toList());
            }
        }

        assertTrue(registrations.contains(RiskAuthenticatorFactory.class.getName()));
        assertTrue(registrations.contains(RiskStepUpConditionFactory.class.getName()));
    }

    @Test
    void exposesEditableUrlsAndMaskedRequiredClientSecret() {
        Map<String, ProviderConfigProperty> properties = new RiskAuthenticatorFactory()
                .getConfigProperties()
                .stream()
                .collect(Collectors.toMap(ProviderConfigProperty::getName, Function.identity()));

        assertEquals(
                ProviderConfigProperty.STRING_TYPE,
                properties.get(RiskAuthenticatorConfigResolver.SERVICE_BASE_URL).getType()
        );
        assertEquals(
                ProviderConfigProperty.STRING_TYPE,
                properties.get(RiskAuthenticatorConfigResolver.TOKEN_ENDPOINT_URL).getType()
        );
        ProviderConfigProperty secret = properties.get(
                RiskAuthenticatorConfigResolver.SERVICE_CLIENT_SECRET
        );
        assertEquals(ProviderConfigProperty.PASSWORD, secret.getType());
        assertTrue(secret.isSecret());
        assertTrue(secret.isRequired());
    }
}
