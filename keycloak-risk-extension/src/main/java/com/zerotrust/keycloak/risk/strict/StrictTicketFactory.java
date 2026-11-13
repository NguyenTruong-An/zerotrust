package com.zerotrust.keycloak.risk.strict;
import org.keycloak.authentication.*;
import org.keycloak.models.*;
import java.util.List;
public final class StrictTicketFactory extends StrictOtpFactoryBase implements AuthenticatorFactory {
    @Override public String getId(){return "d10-auth-ticket";}
    @Override public Authenticator create(KeycloakSession s){return new Authenticator(){
        @Override public void authenticate(AuthenticationFlowContext c){
            var a=c.getAuthenticationSession();
            String ticket=a.getAuthNote(StrictTokenGate.NOTE_TICKET),epoch=a.getAuthNote(StrictTokenGate.NOTE_EPOCH),proof=NativeFlowGuard.proof(a);
            if(ticket==null || epoch==null || !c.getUser().getId().equals(a.getAuthNote("zt.d10.ticket.subject"))
                    || proof!=null && !proof.equals(a.getAuthNote(StrictTokenGate.NOTE_PROOF))) throw AuthorityClient.rejected();
            a.setUserSessionNote(StrictTokenGate.NOTE_TICKET,ticket);a.setUserSessionNote(StrictTokenGate.NOTE_EPOCH,epoch);
            if(proof!=null)a.setUserSessionNote(StrictTokenGate.NOTE_PROOF,proof);
            c.success();
        }
        @Override public void action(AuthenticationFlowContext c){authenticate(c);}
        @Override public boolean requiresUser(){return true;}
        @Override public boolean configuredFor(KeycloakSession s,RealmModel r,UserModel u){return true;}
        @Override public void setRequiredActions(KeycloakSession s,RealmModel r,UserModel u){}
        @Override public void close(){}
    };}
}
