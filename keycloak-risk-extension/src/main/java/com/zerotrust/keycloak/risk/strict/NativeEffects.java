package com.zerotrust.keycloak.risk.strict;

import jakarta.persistence.LockModeType;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.util.JsonSerialization;
import java.util.*;

/** Exact-pin JPA fencing: the native subject lock spans admission, mutation and receipt commit. */
@jakarta.ws.rs.ext.Provider
public final class NativeEffects implements RealmResourceProvider {
    private final KeycloakSession session;
    public NativeEffects(KeycloakSession session){this.session=session;}
    @Override public Object getResource(){return this;}
    @Override public void close(){}
    public record Effect(UUID operationId,String subjectId,long epoch,String effectId,String action) {}
    @POST @Path("effects") @Consumes(MediaType.APPLICATION_JSON) @Produces(MediaType.APPLICATION_JSON)
    public Response effect(Effect effect) {
        var realm=session.getContext().getRealm();
        if(!StrictTokenGate.applies(realm))throw AuthorityClient.rejected();
        var authentication=new AppAuthManager.BearerTokenAuthenticator(session).setRealm(realm).authenticate();
        if(authentication==null)throw AuthorityClient.rejected();
        var token=authentication.getToken();
        var access=token.getResourceAccess("zerotrust-native-security");
        if(!"zerotrust-portal-security".equals(token.getIssuedFor()) || access==null || !access.isUserInRole("security:reset-native")
                || token.getAudience()==null || !Arrays.asList(token.getAudience()).contains("zerotrust-native-security"))throw new ForbiddenException();
        var machine=session.getContext().getRealm().getClientByClientId(token.getIssuedFor());
        var actor=session.users().getUserById(realm,token.getSubject());
        if(machine==null || actor==null || !machine.getId().equals(actor.getServiceAccountClientLink()))throw new ForbiddenException();
        if(effect==null || effect.operationId()==null || effect.effectId()==null || !Set.of("EARLY_LOGOUT","CREDENTIAL_MUTATION","FINAL_LOGOUT","EXTERNAL_RECONCILE").contains(effect.action()))throw AuthorityClient.rejected();
        var em=session.getProvider(JpaConnectionProvider.class).getEntityManager();
        var entity=em.find(UserEntity.class,effect.subjectId(),LockModeType.PESSIMISTIC_WRITE,Map.of("jakarta.persistence.lock.timeout",3000));
        if(entity==null || !realm.getId().equals(entity.getRealmId()))throw AuthorityClient.rejected();
        em.refresh(entity,LockModeType.PESSIMISTIC_WRITE);
        UserModel user=session.users().getUserById(realm,effect.subjectId());
        if(user==null || user.getFederationLink()!=null || user.getServiceAccountClientLink()!=null)throw AuthorityClient.rejected();
        String receipt=effect.operationId()+":"+effect.epoch()+":"+effect.effectId()+":"+effect.action();
        AuthorityClient authority=new AuthorityClient(session);
        if("EXTERNAL_RECONCILE".equals(effect.action())) {
            boolean committed=entity.getAttributes().stream().anyMatch(a->"zt.d10.external-effect".equals(a.getName()) && effect.operationId().toString().equals(a.getValue()));
            if(!committed)throw AuthorityClient.rejected(); // absence/UNKNOWN never clears quarantine
            authority.call("external-confirmation",Map.of("operationId",effect.operationId().toString()));
            return Response.noContent().build();
        }
        if(entity.getAttributes().stream().anyMatch(a->"zt.d10.effect".equals(a.getName()) && receipt.equals(a.getValue()))) {
            // A committed receipt proves this effect already ran; do not replay credential deletion.
            authority.call("native-confirmation",effect);
            return Response.noContent().build();
        }
        authority.call("native-admission",effect);
        if("CREDENTIAL_MUTATION".equals(effect.action())) {
            user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
            user.addRequiredAction("CONFIGURE_RECOVERY_AUTHN_CODES");
            var remove=user.credentialManager().getStoredCredentialsStream()
                    .filter(c->Set.of("otp","recovery-authn-codes").contains(c.getType())).map(c->c.getId()).toList();
            remove.forEach(user.credentialManager()::removeStoredCredentialById);
        } else session.sessions().removeUserSessions(realm,user);
        user.setSingleAttribute("zt.d10.effect",receipt);
        em.flush();
        session.getTransactionManager().enlistAfterCompletion(new AbstractKeycloakTransaction(){
            @Override protected void commitImpl(){try{authority.call("native-confirmation",effect);}catch(RuntimeException ignored){/* durable receipt permits retry */}}
            @Override protected void rollbackImpl(){/* pending remains; retry takes the same native row lock */}
        });
        return Response.noContent().build();
    }
}
