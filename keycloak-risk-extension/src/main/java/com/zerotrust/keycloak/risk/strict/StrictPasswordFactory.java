package com.zerotrust.keycloak.risk.strict;
import org.keycloak.authentication.*;
import org.keycloak.authentication.authenticators.browser.*;
import org.keycloak.models.KeycloakSession;
public final class StrictPasswordFactory extends UsernamePasswordFormFactory {
    @Override public String getId(){return "d10-password";}
    @Override public Authenticator create(KeycloakSession s){return new NativeFlowGuard(new UsernamePasswordForm(),"password",new AuthorityClient(s));}
}
