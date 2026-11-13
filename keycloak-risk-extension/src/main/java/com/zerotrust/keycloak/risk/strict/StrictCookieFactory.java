package com.zerotrust.keycloak.risk.strict;
import org.keycloak.authentication.*;
import org.keycloak.authentication.authenticators.browser.*;
import org.keycloak.models.KeycloakSession;
public final class StrictCookieFactory extends CookieAuthenticatorFactory {
    @Override public String getId(){return "d10-cookie";}
    @Override public Authenticator create(KeycloakSession s){return new NativeFlowGuard(new CookieAuthenticator(),"cookie",new AuthorityClient(s));}
}
