package com.zerotrust.keycloak.risk.strict;
import org.keycloak.Config;
import org.keycloak.events.*;
import org.keycloak.events.admin.*;
import org.keycloak.models.*;
import java.util.*;
/** Synchronous transaction participant, NOT a telemetry listener. Failure marks native TX rollback-only. */
public final class NativeMutationListenerFactory implements EventListenerProviderFactory {
    @Override public boolean isGlobal(){return true;}
    @Override public EventListenerProvider create(KeycloakSession session){return new EventListenerProvider(){
        @Override public void onEvent(Event e){
            if(e==null)return;
            String kind=e.getType().name();
            if((kind.equals("LOGOUT") && e.getError()==null || kind.equals("REFRESH_TOKEN_ERROR") && "invalid_token".equals(e.getError())) && e.getUserId()!=null && e.getSessionId()!=null) {
                if(!StrictTokenGate.applies(session.realms().getRealm(e.getRealmId())))return;
                try{new AuthorityClient(session).call("native-session-revocations",Map.of("subjectId",e.getUserId(),"sessionId",e.getSessionId()));}
                catch(RuntimeException failure){session.getTransactionManager().setRollbackOnly();throw AuthorityClient.unavailable();}
                return;
            }
            if(e.getError()!=null)return;
            if(Set.of("UPDATE_PASSWORD","UPDATE_TOTP","REMOVE_TOTP","UPDATE_CREDENTIAL","REMOVE_CREDENTIAL","DELETE_ACCOUNT").contains(kind))mutate(e.getRealmId(),e.getUserId());
        }
        @Override public void onEvent(AdminEvent e,boolean includeRepresentation){
            if(e==null || e.getError()!=null || e.getResourcePath()==null)return;
            String[] path=e.getResourcePath().split("/");
            if(path.length>=2 && path[0].equals("users")) {
                try{UUID.fromString(path[1]);mutate(e.getRealmId(),path[1]);}catch(IllegalArgumentException ignored){}
            }
        }
        private void mutate(String realmId,String subject){
            RealmModel realm=session.realms().getRealm(realmId);
            if(!StrictTokenGate.applies(realm) || subject==null)return;
            String attribute="zt.d10.nativeMutation."+subject;
            if(session.getAttribute(attribute)!=null)return;
            UserModel user=session.users().getUserById(realm,subject);
            if(user!=null && user.getServiceAccountClientLink()!=null)return;
            session.setAttribute(attribute,Boolean.TRUE);
            try {
                if(user!=null) {
                    var em=session.getProvider(org.keycloak.connections.jpa.JpaConnectionProvider.class).getEntityManager();
                    var local=em.find(org.keycloak.models.jpa.entities.UserEntity.class,subject,jakarta.persistence.LockModeType.PESSIMISTIC_WRITE,Map.of("jakarta.persistence.lock.timeout",3000));
                    if(local==null)throw AuthorityClient.unavailable(); // unsupported/federated storage is quarantined, never silently accepted
                }
                AuthorityClient authority=new AuthorityClient(session);
                UUID operation=UUID.randomUUID();
                authority.call("revocations",Map.of("subjectId",subject,"operationId",operation.toString(),"actorId","keycloak-native","kind","EXTERNAL_MUTATION","quarantine",true,"disabled",user==null || !user.isEnabled()));
                if(user!=null)user.setSingleAttribute("zt.d10.external-effect",operation.toString());
                session.getTransactionManager().enlistAfterCompletion(new AbstractKeycloakTransaction(){
                    @Override protected void commitImpl(){try{authority.call("external-confirmation",Map.of("operationId",operation.toString()));}catch(RuntimeException ignored){/* quarantine remains */}}
                    @Override protected void rollbackImpl(){/* never clear authority pending on rollback */}
                });
            } catch(RuntimeException failure) {
                session.getTransactionManager().setRollbackOnly();
                throw AuthorityClient.unavailable();
            }
        }
        @Override public void close(){}
    };}
    @Override public String getId(){return "d10-native-mutations";}
    @Override public void init(Config.Scope c){}
    @Override public void postInit(KeycloakSessionFactory f){}
    @Override public void close(){}
}
