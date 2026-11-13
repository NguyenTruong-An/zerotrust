package com.zerotrust.keycloak.risk.strict;
import org.junit.jupiter.api.*;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.token.*;
import org.keycloak.representations.*;
import java.util.*;
import jakarta.ws.rs.WebApplicationException;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
class StrictTokenGateTest {
    KeycloakSession session;UserSessionModel nativeSession;UserModel user;ClientModel client;ClientSessionContext clientContext;AuthorityClient authority;StrictTokenGate gate;
    final String subject=UUID.randomUUID().toString(),sid=UUID.randomUUID().toString();
    @BeforeEach void setup(){
        session=mock(KeycloakSession.class,RETURNS_DEEP_STUBS);nativeSession=mock(UserSessionModel.class);user=mock(UserModel.class);client=mock(ClientModel.class);clientContext=mock(ClientSessionContext.class,RETURNS_DEEP_STUBS);authority=mock(AuthorityClient.class);
        when(session.getContext().getRealm().getName()).thenReturn("DoAn");when(clientContext.getClientSession().getUserSession()).thenReturn(nativeSession);when(clientContext.getClientSession().getClient()).thenReturn(client);
        when(nativeSession.getUser()).thenReturn(user);when(nativeSession.getId()).thenReturn(sid);when(user.getId()).thenReturn(subject);when(user.isEnabled()).thenReturn(true);when(client.getClientId()).thenReturn("zerotrust-spa");when(nativeSession.getNote(StrictTokenGate.NOTE_EPOCH)).thenReturn("4");when(nativeSession.getNote(StrictTokenGate.NOTE_TICKET)).thenReturn("fixture-ticket");
        when(authority.call(eq("issuance"),any())).thenReturn(Map.of("epoch",4L));gate=new StrictTokenGate(session,authority);
    }
    AccessToken access(){AccessToken token=new AccessToken();token.subject(subject);token.issuedFor("zerotrust-spa");token.setSessionId(sid);return token;}
    RefreshToken refresh(){var token=new RefreshToken(access(),null,"fixture-refresh-id");token.getOtherClaims().putAll(Map.of("zt_sec_epoch",4L,"zt_sec_ver",1,"zt_sec_sid",sid));return token;}
    TokenPostProcessorContext context(RefreshToken old,AccessToken next,RefreshToken nextRefresh){return new TokenPostProcessorContext(null,old,nextRefresh,next,clientContext);}
    @Test void everyIssuanceChecksAuthorityWithoutPositiveCache(){var a=access();gate.process(context(null,a,null));gate.process(context(null,a,null));verify(authority,times(2)).call(eq("issuance"),any());assertEquals(4L,a.getOtherClaims().get("zt_sec_epoch"));assertEquals(sid,a.getOtherClaims().get("zt_sec_sid"));}
    @Test void rejectedAuthorityNeverStampsNewToken(){when(authority.call(eq("issuance"),any())).thenThrow(AuthorityClient.rejected());var a=access();assertEquals(401,assertThrows(WebApplicationException.class,()->gate.process(context(null,a,null))).getResponse().getStatus());assertFalse(a.getOtherClaims().containsKey("zt_sec_epoch"));}
    @Test void unavailableAuthorityNeverStampsNewToken(){when(authority.call(eq("issuance"),any())).thenThrow(AuthorityClient.unavailable());var a=access();assertEquals(503,assertThrows(WebApplicationException.class,()->gate.process(context(null,a,null))).getResponse().getStatus());assertFalse(a.getOtherClaims().containsKey("zt_sec_epoch"));}
    @Test void legacyRefreshCannotBeUpgradedUsingSessionNotes(){var old=refresh();old.getOtherClaims().clear();assertThrows(WebApplicationException.class,()->gate.process(context(old,access(),null)));verifyNoInteractions(authority);}
    @Test void staleRefreshCannotBeUpgradedToNewEpoch(){var old=refresh();old.getOtherClaims().put("zt_sec_epoch",3L);assertThrows(WebApplicationException.class,()->gate.process(context(old,access(),null)));}
    @Test void refreshCopiesOriginalFactorTimeAndNeverInventsProof(){var old=refresh();old.getOtherClaims().put("zt_mfa_at",1234L);old.getOtherClaims().put("zt_mfa_proof","fixture-proof");when(nativeSession.getNote(StrictTokenGate.NOTE_PROOF)).thenReturn("new-session-proof");var a=access();var r=refresh();gate.process(context(old,a,r));assertEquals(1234L,a.getOtherClaims().get("zt_mfa_at"));assertEquals(1234L,r.getOtherClaims().get("zt_mfa_at"));assertEquals("fixture-proof",a.getOtherClaims().get("zt_mfa_proof"));verify(nativeSession,never()).getNote(StrictTokenGate.NOTE_PROOF);}
    @Test void wrongNativeSubjectAndSessionCannotBeClaimed(){var a=access();a.setSessionId("other-session");assertThrows(WebApplicationException.class,()->gate.process(context(null,a,null)));verifyNoInteractions(authority);}
    @Test void disabledNativeIdentityCannotIssue(){when(user.isEnabled()).thenReturn(false);assertThrows(WebApplicationException.class,()->gate.process(context(null,access(),null)));verifyNoInteractions(authority);}
    @Test void humanCannotUseMachineClientExemption(){when(client.getClientId()).thenReturn("zerotrust-issuer-security");when(client.isServiceAccountsEnabled()).thenReturn(true);when(client.getId()).thenReturn("native-client-id");gate.process(context(null,access(),null));verify(authority).call(eq("issuance"),any());}
    @Test void trueNativeServiceAccountAvoidsAuthorityBootstrapLoop(){when(client.getClientId()).thenReturn("zerotrust-issuer-security");when(client.isServiceAccountsEnabled()).thenReturn(true);when(client.getId()).thenReturn("native-client-id");when(user.getServiceAccountClientLink()).thenReturn("native-client-id");gate.process(context(null,access(),null));verifyNoInteractions(authority);}
}
