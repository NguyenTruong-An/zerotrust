package com.zerotrust.keycloak.risk.authenticator;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

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
}
