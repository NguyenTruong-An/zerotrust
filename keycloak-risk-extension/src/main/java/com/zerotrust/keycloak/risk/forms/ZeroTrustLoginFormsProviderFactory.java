package com.zerotrust.keycloak.risk.forms;

import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProviderFactory;
import org.keycloak.models.KeycloakSession;

public final class ZeroTrustLoginFormsProviderFactory extends FreeMarkerLoginFormsProviderFactory {

    @Override
    public LoginFormsProvider create(KeycloakSession session) {
        return new ZeroTrustLoginFormsProvider(session);
    }

    @Override
    public int order() {
        // Replace the standard renderer by ID while delegating all native rendering.
        return 100;
    }
}
