package com.zerotrust.gateway;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.*;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.*;
import org.springframework.test.web.reactive.server.WebTestClient;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class GatewaySecurityTests {
    static final GatewayMockUpstream upstream=new GatewayMockUpstream();
    @Autowired WebTestClient client;
    @DynamicPropertySource static void config(DynamicPropertyRegistry p) { upstream.properties(p); }
    @AfterAll static void close() { upstream.close(); }
    @Test void realSignedJwtIsValidatedAndOriginalBearerPreserved() throws Exception {
        String token=upstream.token("STUDENT",upstream.issuer(),"zerotrust-api",Instant.now().plusSeconds(60));
        client.get().uri("/api/students/me").header("Authorization","Bearer "+token).exchange().expectStatus().isOk();
        assertTrue(("Bearer "+token).equals(upstream.authorization));
    }
    @Test void missingAndTamperedJwtCannotReachBackend() throws Exception {
        int before=upstream.apiCalls;
        client.get().uri("/api/students/me").exchange().expectStatus().isUnauthorized().expectBody().jsonPath("$.status").isEqualTo(401);
        String token=upstream.token("STUDENT",upstream.issuer(),"zerotrust-api",Instant.now().plusSeconds(60));
        String[] parts=token.split("\\.");parts[1]=Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"changed\"}".getBytes(StandardCharsets.UTF_8));
        client.get().uri("/api/students/me").header("Authorization","Bearer "+String.join(".",parts)).exchange().expectStatus().isUnauthorized();
        assertEquals(before,upstream.apiCalls);
    }
    @Test void wrongIssuerAudienceExpiryAndMissingExpirationAreRejected() throws Exception {
        for (String token:List.of(upstream.token("STUDENT","http://wrong-issuer.invalid","zerotrust-api",Instant.now().plusSeconds(60)),
                upstream.token("STUDENT",upstream.issuer(),"other-audience",Instant.now().plusSeconds(60)),
                upstream.token("STUDENT",upstream.issuer(),"zerotrust-api",Instant.now().minusSeconds(120)),
                upstream.token("STUDENT",upstream.issuer(),"zerotrust-api",null))) {
            client.get().uri("/api/students/me").header("Authorization","Bearer "+token).exchange().expectStatus().isUnauthorized();
        }
    }
    @Test void realmRolesAndForgedHeadersDoNotGrantHigherPrivilege() throws Exception {
        String student=upstream.token("STUDENT",upstream.issuer(),"zerotrust-api",Instant.now().plusSeconds(60));
        client.get().uri("/api/admin/users").headers(h -> {h.setBearerAuth(student);h.set("X-Role","ADMIN");h.set("X-Subject","admin");}).exchange().expectStatus().isForbidden();
        client.get().uri("/api/teachers/me").headers(h -> h.setBearerAuth(student)).exchange().expectStatus().isForbidden();
        String teacher=upstream.token("TEACHER",upstream.issuer(),"zerotrust-api",Instant.now().plusSeconds(60));
        client.get().uri("/api/admin/users").headers(h -> h.setBearerAuth(teacher)).exchange().expectStatus().isForbidden();
    }
    @Test void publicSpaIsNotABffAndDoesNotForwardTokensOrCookies() throws Exception {
        String token=upstream.token("STUDENT",upstream.issuer(),"zerotrust-api",Instant.now().plusSeconds(60));
        client.get().uri("/").headers(h -> {h.setBearerAuth(token);h.set("Cookie","untrusted=value");}).exchange().expectStatus().isOk().expectCookie().doesNotExist("SESSION");
        assertNull(upstream.authorization);assertNull(upstream.cookie);
    }
    @Test void corsAllowsExactOriginAndRejectsForeignOrigin() {
        client.options().uri("/api/students/me").header("Origin","https://portal.qa02c.test:8450").header("Access-Control-Request-Method","GET").exchange()
                .expectStatus().isOk().expectHeader().valueEquals("Access-Control-Allow-Origin","https://portal.qa02c.test:8450");
        client.options().uri("/api/students/me").header("Origin","https://untrusted.invalid").header("Access-Control-Request-Method","GET").exchange().expectStatus().isForbidden();
    }
    @Test void corsPreflightRequiresDistinctRequestAuthority() {
        String trusted="https://portal.qa02c.test:8450";
        var same=org.springframework.mock.web.server.MockServerWebExchange.from(org.springframework.mock.http.server.reactive.MockServerHttpRequest.options(trusted+"/api/students/me").header("Origin",trusted).header("Access-Control-Request-Method","GET"));
        assertFalse(org.springframework.web.cors.reactive.CorsUtils.isCorsRequest(same.getRequest()));
        var cross=org.springframework.mock.web.server.MockServerWebExchange.from(org.springframework.mock.http.server.reactive.MockServerHttpRequest.options("https://portal.qa02c.test/api/students/me").header("Origin",trusted).header("Access-Control-Request-Method","GET"));
        assertTrue(org.springframework.web.cors.reactive.CorsUtils.isCorsRequest(cross.getRequest()));
        assertTrue(org.springframework.web.cors.reactive.CorsUtils.isPreFlightRequest(cross.getRequest()));
        assertEquals(-1,cross.getRequest().getURI().getPort());
    }
}

/** Test-only loopback/JWKS/upstream; no Keycloak, business DB or native QA. */
final class GatewayMockUpstream implements AutoCloseable {
    final HttpServer server;final RSAKey key;
    volatile String authorization,cookie,forwarded,path;volatile int apiCalls;
    GatewayMockUpstream() {
        try {
            KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);KeyPair pair=generator.generateKeyPair();
            key=new RSAKey.Builder((RSAPublicKey)pair.getPublic()).privateKey((RSAPrivateKey)pair.getPrivate()).keyID("qa-unit-key").build();
            server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
            server.createContext("/",e -> {
                String requestPath=e.getRequestURI().getPath();String body;int status=200;
                if (requestPath.equals("/jwks")) body=new JWKSet(key.toPublicJWK()).toString();
                else {
                    authorization=e.getRequestHeaders().getFirst("Authorization");cookie=e.getRequestHeaders().getFirst("Cookie");forwarded=e.getRequestHeaders().getFirst("X-Forwarded-For");path=e.getRequestURI().toString();
                    if (requestPath.startsWith("/api/")) apiCalls++;
                    if (requestPath.endsWith("/slow")) {try {Thread.sleep(700);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();}}
                    status=requestPath.endsWith("/missing")?404:requestPath.endsWith("/failure")?500:200;
                    body="{\"unit_upstream\":true}";
                }
                byte[] bytes=body.getBytes(StandardCharsets.UTF_8);e.getResponseHeaders().set("Content-Type","application/json");
                try {e.sendResponseHeaders(status,bytes.length);e.getResponseBody().write(bytes);}finally{e.close();}
            });server.start();
        }catch(Exception e){throw new IllegalStateException("UNIT_LOOPBACK_SETUP_ERROR",e);}
    }
    String base(){return "http://127.0.0.1:"+server.getAddress().getPort();}
    String issuer(){return base()+"/issuer";}
    void properties(DynamicPropertyRegistry p) {
        p.add("app.routes.backend",this::base);p.add("app.routes.frontend",this::base);
        p.add("app.security.jwt.issuer",this::issuer);p.add("app.security.jwt.jwks",()->base()+"/jwks");
        p.add("app.security.jwt.audience",()->"zerotrust-api");p.add("app.security.cors.origins",()->"https://portal.qa02c.test:8450");
    }
    String token(String role,String issuer,String audience,Instant expiry) throws Exception {
        JWTClaimsSet.Builder claims=new JWTClaimsSet.Builder().subject("00000000-0000-0000-0000-000000000001")
                .issuer(issuer).audience(audience).issueTime(new Date()).claim("realm_access",Map.of("roles",List.of(role)));
        if(expiry!=null) claims.expirationTime(Date.from(expiry));
        SignedJWT jwt=new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),claims.build());jwt.sign(new RSASSASigner(key));return jwt.serialize();
    }
    @Override public void close(){server.stop(0);}
}
