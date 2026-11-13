package com.zerotrust.keycloak.risk.strict;

import org.keycloak.models.*;
import org.keycloak.protocol.oidc.token.*;
import org.keycloak.representations.AccessToken;
import java.math.BigDecimal;
import java.util.*;

/** Called by the native response builder BEFORE token encoding/signing. */
public final class StrictTokenGate implements TokenPostProcessor {
    public static final String EPOCH="zt_sec_epoch", SID="zt_sec_sid", VERSION="zt_sec_ver";
    public static final String NOTE_TICKET="zt.d10.ticket", NOTE_EPOCH="zt.d10.epoch", NOTE_PROOF="zt.d10.proof";
    private static final Set<String> MACHINES=Set.of("zerotrust-issuer-security","zerotrust-portal-security","zerotrust-gateway-security","zerotrust-risk-caller","zerotrust-portal-risk-admin","zerotrust-provisioner");
    private final KeycloakSession session;
    private final AuthorityClient authority;
    public StrictTokenGate(KeycloakSession session,AuthorityClient authority) { this.session=session;this.authority=authority; }
    public static boolean applies(RealmModel realm) { return realm!=null && Objects.equals(realm.getName(),Optional.ofNullable(System.getenv("ZT_SECURITY_REALM")).orElse("DoAn")); }
    public static long epoch(Object value) {
        if(!(value instanceof Number number)) throw AuthorityClient.rejected();
        try { long epoch=new BigDecimal(number.toString()).longValueExact(); if(epoch<1) throw AuthorityClient.rejected();return epoch; }
        catch(ArithmeticException | NumberFormatException e) { throw AuthorityClient.rejected(); }
    }
    public static Map<String,Object> context(String subject,String sid,String client,long epoch) {
        if(subject==null || sid==null || sid.isBlank() || client==null || epoch<1) throw AuthorityClient.rejected();
        return Map.of("subjectId",subject,"sessionId",sid,"clientId",client,"epoch",epoch);
    }
    @Override public void process(TokenPostProcessorContext c) {
        if(!applies(session.getContext().getRealm())) return;
        var nativeSession=c.clientSessionCtx().getClientSession().getUserSession();
        ClientModel client=c.clientSessionCtx().getClientSession().getClient();
        UserModel user=nativeSession.getUser();
        if(!user.isEnabled() || user.getFederationLink()!=null)throw AuthorityClient.rejected();
        // Only native service-account identity, never a human token with a matching azp.
        if(MACHINES.contains(client.getClientId()) && client.isServiceAccountsEnabled()
                && client.getId().equals(user.getServiceAccountClientLink())) return;
        if(c.accessToken()==null || !user.getId().equals(c.accessToken().getSubject())
                || !nativeSession.getId().equals(c.accessToken().getSessionId())) throw AuthorityClient.rejected();
        boolean refresh=c.requestRefreshToken()!=null;
        long expected;
        String ticket=null;
        if(refresh) {
            AccessToken previous=c.requestRefreshToken();
            if(!user.getId().equals(previous.getSubject()) || !nativeSession.getId().equals(previous.getSessionId())
                    || !nativeSession.getId().equals(previous.getOtherClaims().get(SID))
                    || epoch(previous.getOtherClaims().get(VERSION))!=1 || !client.getClientId().equals(previous.getIssuedFor())) throw AuthorityClient.rejected();
            expected=epoch(previous.getOtherClaims().get(EPOCH));
        } else {
            try { expected=Long.parseLong(nativeSession.getNote(NOTE_EPOCH)); }
            catch(RuntimeException e) { throw AuthorityClient.rejected(); }
            ticket=nativeSession.getNote(NOTE_TICKET);
        }
        var request=new HashMap<String,Object>();
        request.put("context",context(user.getId(),nativeSession.getId(),client.getClientId(),expected));
        request.put("ticket",ticket);
        String proof=refresh?null:nativeSession.getNote(NOTE_PROOF);
        request.put("proofId",proof); request.put("codeId",c.code()==null?null:c.code().getId());
        Map<String,Object> result=authority.call("issuance",request);
        long granted=epoch(result.get("epoch"));
        if(granted!=expected) throw AuthorityClient.rejected();
        stamp(c.accessToken(),nativeSession.getId(),granted);
        if(c.refreshToken()!=null) stamp(c.refreshToken(),nativeSession.getId(),granted);
        if(refresh) {
            // Copy original signed factor evidence. Refresh never samples time or session notes.
            for(String claim:MFA_CLAIMS) {
                Object value=c.requestRefreshToken().getOtherClaims().get(claim);
                if(value!=null) { c.accessToken().getOtherClaims().put(claim,value); if(c.refreshToken()!=null)c.refreshToken().getOtherClaims().put(claim,value); }
            }
        } else if(result.get("proof") instanceof Map<?,?> p) {
            Map<String,Object> claims=Map.of("zt_mfa_at",p.get("factorAt"),"zt_mfa_method",p.get("method"),"zt_mfa_subject",user.getId(),"zt_mfa_client",client.getClientId(),"zt_mfa_proof",p.get("proofId"),"zt_mfa_target",p.get("targetId"),"zt_mfa_action",p.get("action"),"zt_mfa_attempt",p.get("attemptId"),"zt_mfa_sid",nativeSession.getId());
            c.accessToken().getOtherClaims().putAll(claims);if(c.refreshToken()!=null)c.refreshToken().getOtherClaims().putAll(claims);
        }
        if(!refresh) {
            nativeSession.removeNote(NOTE_TICKET);
            nativeSession.removeNote(NOTE_PROOF);
        }
    }
    private static final Set<String> MFA_CLAIMS=Set.of("zt_mfa_at","zt_mfa_method","zt_mfa_subject","zt_mfa_client","zt_mfa_proof","zt_mfa_target","zt_mfa_action","zt_mfa_attempt","zt_mfa_sid");
    private void stamp(AccessToken token,String sid,long epoch) {
        MFA_CLAIMS.forEach(token.getOtherClaims()::remove);
        token.getOtherClaims().put(EPOCH,epoch);token.getOtherClaims().put(SID,sid);token.getOtherClaims().put(VERSION,1);
    }
    @Override public void close() {}
}
