package com.zerotrust.gateway;

import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.*;
import org.springframework.test.web.reactive.server.WebTestClient;
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties="spring.cloud.gateway.server.webflux.httpclient.response-timeout=100ms")
@DirtiesContext(classMode=DirtiesContext.ClassMode.AFTER_CLASS)
class GatewayRouteTests {
    static final GatewayMockUpstream upstream=new GatewayMockUpstream();
    @Autowired WebTestClient client;
    @DynamicPropertySource static void config(DynamicPropertyRegistry p){upstream.properties(p);}
    @AfterAll static void close(){upstream.close();}
    String token() throws Exception{return upstream.token("STUDENT",upstream.issuer(),"zerotrust-api",Instant.now().plusSeconds(60));}
    @Test void apiPathAndQueryPreservedAndSpoofedForwardingDiscarded() throws Exception {
        client.get().uri("/api/students/me?keyword=test").headers(h->{h.setBearerAuth(tokenUnchecked());h.set("X-Forwarded-For","203.0.113.1");h.set("Forwarded","for=203.0.113.1");h.set("Cookie","session=fake");}).exchange()
                .expectStatus().isOk().expectHeader().valueEquals("Cache-Control","no-store").expectHeader().exists("X-Correlation-ID");
        assertEquals("/api/students/me?keyword=test",upstream.path);assertNull(upstream.forwarded);assertNull(upstream.cookie);
    }
    private String tokenUnchecked(){try{return token();}catch(Exception e){throw new IllegalStateException(e);}}
    @Test void missingApiDoesNotFallThroughToPortal() throws Exception {
        client.get().uri("/api/students/missing").headers(h->h.setBearerAuth(tokenUnchecked())).exchange().expectStatus().isNotFound();
        assertEquals("/api/students/missing",upstream.path);
    }
    @Test void upstreamFailureIsNotReportedAsSuccess(){client.get().uri("/api/students/failure").headers(h->h.setBearerAuth(tokenUnchecked())).exchange().expectStatus().is5xxServerError();}
    @Test void configuredResponseTimeoutIsBounded(){client.get().uri("/api/students/slow").headers(h->h.setBearerAuth(tokenUnchecked())).exchange().expectStatus().isEqualTo(504);}
}
