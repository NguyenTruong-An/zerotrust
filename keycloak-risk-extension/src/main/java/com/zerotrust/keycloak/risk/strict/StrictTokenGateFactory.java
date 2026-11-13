package com.zerotrust.keycloak.risk.strict;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.token.*;
public final class StrictTokenGateFactory implements TokenPostProcessorFactory {
    @Override public TokenPostProcessor create(KeycloakSession session) {
        // Delay credential loading until a protected human flow actually reaches issuance.
        return new TokenPostProcessor() {
            @Override public void process(TokenPostProcessorContext c) { if(StrictTokenGate.applies(session.getContext().getRealm())) new StrictTokenGate(session,new AuthorityClient(session)).process(c); }
            @Override public void close() {}
        };
    }
    @Override public String getId() { return "zerotrust-strict-security"; }
}
