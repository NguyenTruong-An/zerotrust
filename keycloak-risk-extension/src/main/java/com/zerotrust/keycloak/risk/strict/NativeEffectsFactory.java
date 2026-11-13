package com.zerotrust.keycloak.risk.strict;
import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.services.resource.*;
public final class NativeEffectsFactory implements RealmResourceProviderFactory {
    @Override public RealmResourceProvider create(KeycloakSession s){return new NativeEffects(s);}
    @Override public String getId(){return "d10-security";}
    @Override public void init(Config.Scope c){}
    @Override public void postInit(KeycloakSessionFactory f){}
    @Override public void close(){}
}
