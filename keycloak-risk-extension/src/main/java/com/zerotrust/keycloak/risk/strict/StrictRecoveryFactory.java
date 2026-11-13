package com.zerotrust.keycloak.risk.strict;
import org.keycloak.authentication.*;
import org.keycloak.authentication.authenticators.browser.*;
import org.keycloak.models.KeycloakSession;
public final class StrictRecoveryFactory extends RecoveryAuthnCodesFormAuthenticatorFactory {
    @Override public String getId(){return "d10-recovery";}
    @Override public Authenticator create(KeycloakSession s){
        var guard=new NativeFlowGuard(new RecoveryAuthnCodesFormAuthenticator(s),"recovery-authn-codes",new AuthorityClient(s));
        return new RecoveryAuthnCodesFormAuthenticator(s){
            @Override public void authenticate(AuthenticationFlowContext c){guard.authenticate(c);}
            @Override public void action(AuthenticationFlowContext c){guard.action(c);}
        };
    }
}
