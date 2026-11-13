package com.zerotrust.zerotrust.security;
import org.junit.jupiter.api.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import com.zerotrust.zerotrust.exception.WebException;
import java.time.*;
import java.util.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;
class StrictResetOrchestratorTest {
    static final Instant NOW=Instant.parse("2026-11-13T00:00:00Z");
    final String actor=UUID.randomUUID().toString(),target=UUID.randomUUID().toString(),proof=UUID.randomUUID().toString();
    final StrictSecurityAuthorityClient authority=mock(StrictSecurityAuthorityClient.class);
    final FreshAdminMfaGuard guard=new FreshAdminMfaGuard(Clock.fixed(NOW,ZoneOffset.UTC),Duration.ofSeconds(300),"zerotrust-spa");
    final StrictResetOrchestrator reset=new StrictResetOrchestrator(authority,guard);
    Map<String,Object> claims(){var c=new HashMap<String,Object>();c.putAll(Map.of("sub",actor,"azp","zerotrust-spa","sid","fixture-session","zt_mfa_sid","fixture-session","zt_mfa_subject",actor,"zt_mfa_client","zerotrust-spa","zt_mfa_method","otp","zt_mfa_at",NOW.getEpochSecond(),"zt_mfa_proof",proof));c.putAll(Map.of("zt_mfa_action","MFA_RESET","zt_mfa_target",target,"zt_mfa_attempt","fixture-auth-attempt"));return c;}
    JwtAuthenticationToken auth(Map<String,Object> c){return new JwtAuthenticationToken(Jwt.withTokenValue("synthetic-not-native").header("alg","RS256").claims(v->v.putAll(c)).build(),List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));}
    @Test void missingActionBindingsCannotStartAnyResetEffect(){for(String key:List.of("zt_mfa_proof","zt_mfa_action","zt_mfa_target","zt_mfa_sid","zt_mfa_attempt")){var c=claims();c.remove(key);assertThatThrownBy(()->reset.reset(auth(c),target)).isInstanceOf(WebException.class);}verifyNoInteractions(authority);}
    @Test void wrongActionTargetRequesterClientSessionAndOldFactorAreRejected(){for(String key:List.of("zt_mfa_action","zt_mfa_target","zt_mfa_subject","zt_mfa_client","zt_mfa_sid")){var c=claims();c.put(key,"different");assertThatThrownBy(()->reset.reset(auth(c),target)).isInstanceOf(WebException.class);}var old=claims();old.put("zt_mfa_at",NOW.minusSeconds(301).getEpochSecond());old.put("iat",NOW);old.put("auth_time",NOW.getEpochSecond());assertThatThrownBy(()->reset.reset(auth(old),target)).isInstanceOf(WebException.class);verifyNoInteractions(authority);}
    @Test void completeOperationDoesNotReplayAnyNativeEffect(){when(authority.post(eq("reset-next"),any())).thenReturn(Map.of("completed",true));reset.resume(UUID.randomUUID().toString());verify(authority,never()).nativeEffect(any());}
    @Test void durableStagesAreRequestedInOrderAndPortalNeverClaimsNativeCompletion(){String op=UUID.randomUUID().toString();var first=Map.<String,Object>of("action","EARLY_LOGOUT","effectId","1");var second=Map.<String,Object>of("action","CREDENTIAL_MUTATION","effectId","2");var third=Map.<String,Object>of("action","FINAL_LOGOUT","effectId","3");when(authority.post(eq("reset-next"),any())).thenReturn(first,second,third,Map.of("completed",true));reset.resume(op);var order=inOrder(authority);for(var effect:List.of(first,second,third)){order.verify(authority).post(eq("reset-next"),any());order.verify(authority).nativeEffect(effect);}order.verify(authority).post(eq("reset-next"),any());order.verifyNoMoreInteractions();}
    @Test void unknownNativeOutcomeStopsAndResumeUsesSameDurableEffect(){String op=UUID.randomUUID().toString();var effect=Map.<String,Object>of("effectId",UUID.randomUUID().toString(),"action","CREDENTIAL_MUTATION");when(authority.post(eq("reset-next"),any())).thenReturn(effect);doThrow(new StrictSecurityAuthorityClient.Unavailable()).when(authority).nativeEffect(effect);assertThatThrownBy(()->reset.resume(op)).isInstanceOf(StrictSecurityAuthorityClient.Unavailable.class);verify(authority,times(1)).nativeEffect(effect);reset(authority);when(authority.post(eq("reset-next"),any())).thenReturn(effect,Map.of("completed",true));reset.resume(op);verify(authority).nativeEffect(effect);}
    @Test void authorityOutageBeforeBeginHasNoNativeSideEffects(){when(authority.context(any())).thenReturn(Map.of());when(authority.post(eq("resets"),any())).thenThrow(new StrictSecurityAuthorityClient.Unavailable());assertThatThrownBy(()->reset.reset(auth(claims()),target)).isInstanceOf(WebException.class);verify(authority,never()).nativeEffect(any());}
}
