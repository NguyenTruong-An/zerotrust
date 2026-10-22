package com.zerotrust.gateway;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.*;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import java.net.URI;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.jupiter.api.Assertions.*;

class GatewayHeaderTests {
    @ParameterizedTest @ValueSource(strings={"/api/%2fadmin/users","/api/%5cadmin","/api/%2e%2e/admin","/api/%252fadmin","/api//admin","/api/../admin","/api/students;role=ADMIN"})
    void ambiguousPathsRejectedBeforeDownstream(String path){
        var exchange=MockServerWebExchange.from(MockServerHttpRequest.method(HttpMethod.GET,URI.create(path)));AtomicBoolean called=new AtomicBoolean();
        assertEquals(path,exchange.getRequest().getURI().getRawPath(),"Fixture must preserve the original ambiguous path");
        StepVerifier.create(new CanonicalRequestFilter().filter(exchange,e->{called.set(true);return Mono.empty();})).verifyComplete();
        assertEquals(HttpStatus.BAD_REQUEST,exchange.getResponse().getStatusCode());assertFalse(called.get());
    }
    @Test void bearerIsRetainedButBrowserAuthorityHeadersAreRemoved(){
        var exchange=MockServerWebExchange.from(MockServerHttpRequest.get("/api/students/me").header("Authorization","Bearer unit-marker")
                .header("X-Role","ADMIN").header("X-User-Id","other").header("Forwarded","for=other").header("X-Forwarded-Proto","https").header("X-Correlation-ID","forged"));
        StepVerifier.create(new CanonicalRequestFilter().filter(exchange,e->{
            assertEquals("Bearer unit-marker",e.getRequest().getHeaders().getFirst("Authorization"));
            assertNull(e.getRequest().getHeaders().getFirst("X-Role"));assertNull(e.getRequest().getHeaders().getFirst("Forwarded"));
            assertNotEquals("forged",e.getRequest().getHeaders().getFirst("X-Correlation-ID"));return Mono.empty();
        })).verifyComplete();
    }
    @Test void finalOutgoingBoundaryRemovesFrameworkForwardingHeaders(){
        HttpHeaders input=new HttpHeaders();input.set("Authorization","Bearer unit-marker");input.set("X-Forwarded-For","peer");input.set("Forwarded","for=peer");
        var exchange=MockServerWebExchange.from(MockServerHttpRequest.get("/api/students/me"));
        HttpHeaders filtered=new GatewayRoutesConfig.OutgoingHeaders().filter(input,exchange);
        assertNull(filtered.getFirst("Forwarded"));assertNull(filtered.getFirst("X-Forwarded-For"));assertEquals("Bearer unit-marker",filtered.getFirst("Authorization"));
    }
}
