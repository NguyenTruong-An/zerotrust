package com.zerotrust.zerotrust.security;
import org.junit.jupiter.api.*;
import org.springframework.mock.web.*;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import tools.jackson.databind.ObjectMapper;
import java.util.*;
import java.util.concurrent.atomic.*;
import static org.junit.jupiter.api.Assertions.*;
class StrictSecurityStateFilterTest {
    @AfterEach void clear(){SecurityContextHolder.clearContext();}
    Jwt jwt(){return Jwt.withTokenValue("synthetic-not-native").header("alg","RS256").subject(UUID.randomUUID().toString()).claim("sid","s").claim("zt_sec_sid","s").claim("azp","zerotrust-spa").claim("zt_sec_ver",1).claim("zt_sec_epoch",4L).build();}
    int perform(StrictSecurityStateFilter filter,Jwt jwt,AtomicInteger downstream)throws Exception{SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt,List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_STUDENT"))));var request=new MockHttpServletRequest("GET","/api/students/me");var response=new MockHttpServletResponse();filter.doFilter(request,response,(q,s)->downstream.incrementAndGet());return response.getStatus();}
    @Test void revokedAndUnavailableRejectDirectBackendBeforeApplication()throws Exception{var downstream=new AtomicInteger();var rejected=new StrictSecurityAuthorityClient(new MockEnvironment(),new ObjectMapper()){@Override public void authorize(Jwt jwt){throw new Rejected();}};assertEquals(401,perform(new StrictSecurityStateFilter(rejected),jwt(),downstream));var unavailable=new StrictSecurityAuthorityClient(new MockEnvironment(),new ObjectMapper()){@Override public void authorize(Jwt jwt){throw new Unavailable();}};assertEquals(503,perform(new StrictSecurityStateFilter(unavailable),jwt(),downstream));assertEquals(0,downstream.get());}
    @Test void noCachedAllowSurvivesARevocationBetweenRequests()throws Exception{var revoked=new AtomicBoolean();var calls=new AtomicInteger();var downstream=new AtomicInteger();var client=new StrictSecurityAuthorityClient(new MockEnvironment(),new ObjectMapper()){@Override public void authorize(Jwt jwt){context(jwt);calls.incrementAndGet();if(revoked.get())throw new Rejected();}};var filter=new StrictSecurityStateFilter(client);var token=jwt();assertEquals(200,perform(filter,token,downstream));revoked.set(true);assertEquals(401,perform(filter,token,downstream));assertEquals(2,calls.get());assertEquals(1,downstream.get());}
    @Test void legacyMissingAndIncompatibleClaimsCannotFallBackToJwtOnly()throws Exception{var client=new StrictSecurityAuthorityClient(new MockEnvironment(),new ObjectMapper());for(String key:List.of("zt_sec_epoch","zt_sec_sid","zt_sec_ver","sid","azp")){var claims=new HashMap<>(jwt().getClaims());claims.remove(key);var invalid=Jwt.withTokenValue("synthetic").header("alg","RS256").claims(c->c.putAll(claims)).build();assertEquals(401,perform(new StrictSecurityStateFilter(client),invalid,new AtomicInteger()));}}
    @Test void healthyJwtWithUnconfiguredAuthorityIs503()throws Exception{assertEquals(503,perform(new StrictSecurityStateFilter(new StrictSecurityAuthorityClient(new MockEnvironment(),new ObjectMapper())),jwt(),new AtomicInteger()));}
    @Test void encodedApiPrefixCannotSkipTheBackendGate()throws Exception {
        var client=new StrictSecurityAuthorityClient(new MockEnvironment(),new ObjectMapper()){@Override public void authorize(Jwt jwt){throw new Rejected();}};
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt(),List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN"))));
        var response=new MockHttpServletResponse();var called=new AtomicInteger();
        new StrictSecurityStateFilter(client).doFilter(new MockHttpServletRequest("GET","/%61pi/admin/users"),response,(q,s)->called.incrementAndGet());
        assertEquals(401,response.getStatus());assertEquals(0,called.get());
    }
}
