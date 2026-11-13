package com.zerotrust.keycloak.risk.strict;

import org.keycloak.authentication.*;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import java.lang.reflect.*;
import java.util.*;

/** Delegates validation to Keycloak. Intercepts ONLY the native success callback. */
public final class NativeFlowGuard implements Authenticator {
    private final Authenticator delegate;
    private final String kind;
    private final AuthorityClient authority;
    public NativeFlowGuard(Authenticator delegate,String kind,AuthorityClient authority) { this.delegate=delegate;this.kind=kind;this.authority=authority; }
    public static String attempt(AuthenticationSessionModel a) { return a.getParentSession().getId()+":"+a.getTabId(); }
    @SuppressWarnings("unchecked")
    public static String proof(AuthenticationSessionModel a) {
        String claims=a.getClientNote("claims"); if(claims==null) return null;
        try {
            var root=JsonSerialization.readValue(claims,Map.class);
            if(!(root.get("id_token") instanceof Map<?,?> access) || !(access.get("zt_action_proof") instanceof Map<?,?> p)) return null;
            return UUID.fromString((String)p.get("value")).toString();
        } catch(Exception e) { throw AuthorityClient.rejected(); }
    }
    private AuthenticationFlowContext wrapped(AuthenticationFlowContext c) {
        return (AuthenticationFlowContext)Proxy.newProxyInstance(getClass().getClassLoader(),new Class<?>[]{AuthenticationFlowContext.class},(p,m,args)->{
            if(m.getName().equals("attachUserSession") && kind.equals("cookie")) {
                UserSessionModel s=(UserSessionModel)args[0];
                long epoch;
                try { epoch=Long.parseLong(s.getNote(StrictTokenGate.NOTE_EPOCH)); } catch(RuntimeException e) {throw AuthorityClient.rejected();}
                authority.call("sso-authorizations",StrictTokenGate.context(s.getUser().getId(),s.getId(),c.getAuthenticationSession().getClient().getClientId(),epoch));
                if(proof(c.getAuthenticationSession())!=null) throw AuthorityClient.rejected(); // action proof requires a fresh factor flow
            }
            if(m.getName().equals("success") && !kind.equals("cookie")) {
                var a=c.getAuthenticationSession();
                if(kind.equals("password")) {
                    if(!Objects.equals(a.getAuthNote("zt.d10.ticket.subject"),c.getUser().getId())) throw AuthorityClient.rejected();
                } else {
                    String nonce=proof(a);
                    if(nonce!=null) {
                        long factorAt=java.time.Instant.now().getEpochSecond();
                        authority.call("proofs",Map.of("proofId",nonce,"actorId",c.getUser().getId(),"clientId",a.getClient().getClientId(),"attemptId",attempt(a),"method",kind,"factorAt",factorAt));
                        a.setAuthNote(StrictTokenGate.NOTE_PROOF,nonce);
                    }
                }
            }
            try { return m.invoke(c,args); } catch(InvocationTargetException e) { throw e.getCause(); }
        });
    }
    private void beginPassword(AuthenticationFlowContext c) {
        String username=c.getHttpRequest().getDecodedFormParameters().getFirst("username");
        UserModel user=c.getUser();
        if(user==null && username!=null) {
            user=c.getSession().users().getUserByUsername(c.getRealm(),username);
            if(user==null && c.getRealm().isLoginWithEmailAllowed()) user=c.getSession().users().getUserByEmail(c.getRealm(),username);
        }
        if(user==null) return; // native validator handles unknown identity
        var a=c.getAuthenticationSession();
        var result=authority.call("authentications",Map.of("subjectId",user.getId(),"clientId",a.getClient().getClientId(),"attemptId",attempt(a)));
        a.setAuthNote(StrictTokenGate.NOTE_TICKET,(String)result.get("ticket"));
        a.setAuthNote(StrictTokenGate.NOTE_EPOCH,Long.toString(StrictTokenGate.epoch(result.get("epoch"))));
        a.setAuthNote("zt.d10.ticket.subject",user.getId());
    }
    @Override public void authenticate(AuthenticationFlowContext c) {
        try {delegate.authenticate(wrapped(c));}
        catch(jakarta.ws.rs.WebApplicationException rejected) {
            if(!kind.equals("cookie") || rejected.getResponse().getStatus()!=401)throw rejected;
            // A rejected SSO cookie may only continue through a NEW primary/factor flow.
            // No session is attached, no code is issued, and authority outage never takes this path.
            org.keycloak.services.managers.AuthenticationManager.expireIdentityCookie(c.getSession());
            c.clearUser();c.getAuthenticationSession().removeAuthNote("SSO_AUTH");c.attempted();
        }
    }
    @Override public void action(AuthenticationFlowContext c) { if(kind.equals("password"))beginPassword(c);delegate.action(wrapped(c)); }
    @Override public boolean requiresUser() {return delegate.requiresUser();}
    @Override public boolean configuredFor(KeycloakSession s,RealmModel r,UserModel u) {return delegate.configuredFor(s,r,u);}
    @Override public void setRequiredActions(KeycloakSession s,RealmModel r,UserModel u) {delegate.setRequiredActions(s,r,u);}
    @Override public void close() {delegate.close();}
}
