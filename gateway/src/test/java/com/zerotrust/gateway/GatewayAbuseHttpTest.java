package com.zerotrust.gateway;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.http.codec.autoconfigure.HttpCodecsProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.*;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.netty.http.client.HttpClient;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT,properties={
        "server.address=127.0.0.1","PUBLIC_DEMO_MODE=public-demo","PUBLIC_DEMO_ACADEMIC_READ_ONLY=true",
        "GATEWAY_TRUSTED_PROXY_CIDRS=127.0.0.1/32","app.abuse.api-bytes=1024","app.abuse.static-bytes=128",
        "app.abuse.api-rate=1","app.abuse.api-burst=3","app.abuse.subject-concurrency=1"})
@ActiveProfiles("public-demo")
@AutoConfigureWebTestClient
@DirtiesContext(classMode=DirtiesContext.ClassMode.AFTER_CLASS)
class GatewayAbuseHttpTest {
    static final GatewayMockUpstream upstream=new GatewayMockUpstream();
    @Autowired WebTestClient client;
    // Routing/abuse contracts only: strict authority semantics are covered by GatewaySecurityTests.
    @org.springframework.test.context.bean.override.mockito.MockitoBean StrictSecurityAuthorityClient authority;
    @Autowired HttpCodecsProperties codecs;
    @Autowired org.springframework.cloud.gateway.config.HttpClientProperties upstreamSettings;
    @LocalServerPort int port;
    @MockitoBean(name="gatewayAdmissionClock") LongSupplier clock;
    final AtomicLong nanos=new AtomicLong();
    @DynamicPropertySource static void config(DynamicPropertyRegistry p){upstream.properties(p);}
    @BeforeEach void time(){when(clock.getAsLong()).thenAnswer(i->nanos.get());}
    @AfterAll static void close(){upstream.close();}
    String token(String subject,String role)throws Exception{
        var claims=new JWTClaimsSet.Builder().issuer(upstream.issuer()).subject(subject).audience("zerotrust-api")
                .expirationTime(Date.from(Instant.now().plusSeconds(300))).claim("realm_access",Map.of("roles",List.of(role))).build();
        var jwt=new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(upstream.key.getKeyID()).build(),claims);
        jwt.sign(new RSASSASigner(upstream.key));return jwt.serialize();
    }
    @Test void signedSubjectsBehindOneNatHaveSeparateBurstAndSpoofedIpCannotResetQuota()throws Exception{
        String a=token("nat-teacher-a","STUDENT"),b=token("nat-teacher-b","STUDENT");
        for(int i=0;i<3;i++)get(a,"198.51.100.10").expectStatus().isOk();
        int before=upstream.apiCalls;
        get(a,"203.0.113.99").expectStatus().isEqualTo(429).expectHeader().valueEquals("Retry-After","1")
                .expectBody().jsonPath("$.error").isEqualTo("REQUEST_REJECTED");
        assertEquals(before,upstream.apiCalls);get(b,"198.51.100.10").expectStatus().isOk();
        nanos.addAndGet(1_000_000_000L);get(a,"198.51.100.10").expectStatus().isOk();
    }
    WebTestClient.ResponseSpec get(String bearer,String ip){return client.get().uri("/api/students/me")
            .headers(h->{h.setBearerAuth(bearer);h.set("X-Forwarded-For",ip);h.set("Forwarded","for=9.9.9.9");h.set("X-Real-IP","8.8.8.8");})
            .exchange();}
    @Test void declaredOversizedAndSmallBodiesReturnReal413And200()throws Exception{
        String bearer=token("body-length","ADMIN");int before=upstream.apiCalls;
        client.post().uri("/api/admin/users").headers(h->{h.setBearerAuth(bearer);h.set("X-Forwarded-For","198.51.100.10");})
                .bodyValue("x".repeat(1025)).exchange().expectStatus().isEqualTo(413);
        assertEquals(before,upstream.apiCalls);
        client.post().uri("/api/admin/users").headers(h->{h.setBearerAuth(bearer);h.set("X-Forwarded-For","198.51.100.10");})
                .bodyValue("small").exchange().expectStatus().isOk();assertEquals(before+1,upstream.apiCalls);
    }
    @Test void chunkedUnknownLengthCannotBypassAndSmallChunkedSucceeds()throws Exception{
        String bearer=token("chunked","ADMIN");int before=upstream.apiCalls;
        assertEquals(413,chunk(bearer,new byte[700],new byte[700]));assertEquals(before,upstream.apiCalls);
        assertEquals(200,chunk(bearer,new byte[20],new byte[20]));assertEquals(before+1,upstream.apiCalls);
    }
    int chunk(String bearer,byte[]a,byte[]b){
        return HttpClient.create().host("127.0.0.1").port(port).headers(h->{h.set("Authorization","Bearer "+bearer);h.set("X-Forwarded-For","198.51.100.10");})
                .post().uri("/api/admin/users").send(Flux.just(io.netty.buffer.Unpooled.wrappedBuffer(a),io.netty.buffer.Unpooled.wrappedBuffer(b)))
                .responseSingle((response,body)->body.thenReturn(response.status().code())).block(Duration.ofSeconds(10));
    }
    @Test void authAndRbacStillRejectBeforeUpstreamAndForwardingCannotGrantRoles()throws Exception{
        int before=upstream.apiCalls;
        client.get().uri("/api/admin/users").header("X-Forwarded-For","198.51.100.10").exchange().expectStatus().isUnauthorized();
        client.get().uri("/api/admin/users").headers(h->{h.setBearerAuth(uncheckedStudent());h.set("X-Forwarded-For","198.51.100.10");h.set("X-Role","ADMIN");})
                .exchange().expectStatus().isForbidden();assertEquals(before,upstream.apiCalls);
    }
    String uncheckedStudent(){try{return token("rbac","STUDENT");}catch(Exception e){throw new IllegalStateException(e);}}

    @Test
    void operatorPathsReturn404WithoutRoutingForEveryBusinessRoleAndAnonymous() throws Exception {
        var tokens = Arrays.asList(null, token("operator-probe-admin", "ADMIN"),
                token("operator-probe-student", "STUDENT"));
        String lastPath = upstream.path;
        int apiCalls = upstream.apiCalls;
        for (String bearer : tokens) {
            for (String path : List.of("/observatory/index.html", "/api/admin/observatory/export",
                    "/scripts/observation/viewer.js", "/.local-legacy/risk-observation/latest/index.json",
                    "/presentation/risk-observatory-evidence-20261103-L1/evidence.json",
                    "/api/%6fbservatory/raw-traces", "/internal/v1/risk/evaluations")) {
                client.get().uri(java.net.URI.create("http://127.0.0.1:" + port + path)).headers(headers -> {
                    headers.set("X-Forwarded-For", "198.51.100.10");
                    if (bearer != null) headers.setBearerAuth(bearer);
                }).exchange().expectStatus().isNotFound().expectBody().isEmpty();
            }
        }
        assertEquals(lastPath, upstream.path);
        assertEquals(apiCalls, upstream.apiCalls);
    }
    @Test void malformedForwardingIsRejectedAtHttpBoundary(){
        for(String ip:List.of("198.51.100.10, 127.0.0.1","unknown","::ffff:192.0.2.1"))
            client.get().uri("/").header("X-Forwarded-For",ip).exchange().expectStatus().isBadRequest();
        client.get().uri("/").exchange().expectStatus().isBadRequest();
        client.get().uri("/").header("X-Forwarded-For","198.51.100.1","198.51.100.2").exchange().expectStatus().isBadRequest();
    }
    @Test void nativeHttpHeaderLimitRejectsBeforeUpstream(){
        int before=upstream.apiCalls;
        client.get().uri("/").header("X-Forwarded-For","198.51.100.10").header("X-Padding","x".repeat(17000))
                .exchange().expectStatus().isEqualTo(431);
        assertEquals(before,upstream.apiCalls);
    }
    @Test void trustedProxyCanPresentAnIpv6ClientWithoutForwardingIdentityDownstream(){
        client.get().uri("/").header("X-Forwarded-For","2001:DB8::1").header("Forwarded","for=10.0.0.1")
                .header("X-Real-IP","10.0.0.1").exchange().expectStatus().isOk();
        assertNull(upstream.forwarded);
    }
    @Test void concurrentHttpRequestsForOneSubjectReturn429AndReleaseAfterCompletion()throws Exception{
        var entered=new java.util.concurrent.CountDownLatch(1);var release=new java.util.concurrent.CountDownLatch(1);
        upstream.server.createContext("/api/admin/block",exchange->{
            entered.countDown();try{if(!release.await(5,java.util.concurrent.TimeUnit.SECONDS))throw new IllegalStateException("fixture deadline");}
            catch(InterruptedException interrupted){Thread.currentThread().interrupt();}
            byte[] body="{}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            try{exchange.sendResponseHeaders(200,body.length);exchange.getResponseBody().write(body);}finally{exchange.close();}
        });
        String bearer=token("concurrent","ADMIN");
        var first=java.util.concurrent.CompletableFuture.supplyAsync(()->client.get().uri("/api/admin/block")
                .headers(h->{h.setBearerAuth(bearer);h.set("X-Forwarded-For","198.51.100.10");}).exchange().expectStatus().isOk());
        try{
            assertTrue(entered.await(5,java.util.concurrent.TimeUnit.SECONDS));
            client.get().uri("/api/admin/users").headers(h->{h.setBearerAuth(bearer);h.set("X-Forwarded-For","198.51.100.10");})
                    .exchange().expectStatus().isEqualTo(429).expectHeader().valueEquals("Retry-After","1");
        }finally{release.countDown();}
        first.get(5,java.util.concurrent.TimeUnit.SECONDS);
        client.get().uri("/api/admin/users").headers(h->{h.setBearerAuth(bearer);h.set("X-Forwarded-For","198.51.100.10");})
                .exchange().expectStatus().isOk();
    }
    @Test void upstreamTimeoutAndFixedPoolBindToActualGatewayClient(){
        assertEquals(org.springframework.cloud.gateway.config.HttpClientProperties.Pool.PoolType.FIXED,upstreamSettings.getPool().getType());
        assertEquals(32,upstreamSettings.getPool().getMaxConnections());assertEquals(2000L,upstreamSettings.getPool().getAcquireTimeout());
        assertEquals(Duration.ofSeconds(5),upstreamSettings.getResponseTimeout());
        assertEquals(Duration.ofSeconds(15),upstreamSettings.getPool().getMaxIdleTime());
        assertEquals(Duration.ofSeconds(60),upstreamSettings.getPool().getMaxLifeTime());
        assertEquals(1024L * 1024, codecs.getMaxInMemorySize().toBytes());
    }
}
