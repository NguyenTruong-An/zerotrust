package com.zerotrust.keycloak.risk.strict;
import org.keycloak.authentication.*;
import org.keycloak.authentication.authenticators.browser.*;
import org.keycloak.models.KeycloakSession;
public final class StrictOtpFactory extends OTPFormAuthenticatorFactory {
    @Override public String getId(){return "d10-otp";}
    @Override public Authenticator create(KeycloakSession s){
        var guard=new NativeFlowGuard(new OTPFormAuthenticator(),"otp",new AuthorityClient(s));
        // Preserve CredentialValidator/native type: Keycloak uses it when selecting ALTERNATIVE factors.
        return new OTPFormAuthenticator(){
            @Override public void authenticate(AuthenticationFlowContext c){guard.authenticate(c);}
            @Override public void action(AuthenticationFlowContext c){guard.action(c);}
        };
    }
}
