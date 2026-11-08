package com.zerotrust.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.*;
import reactor.test.StepVerifier;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.jupiter.api.Assertions.*;

class GatewayAbuseFilterTest {
    static org.springframework.web.server.ServerWebExchange exchange(Long declared,int actual){
        var request=MockServerHttpRequest.post("/api/students/me");
        if(declared!=null)request.header("Content-Length",declared.toString());
        var e=MockServerWebExchange.from(request.body(Flux.just(new DefaultDataBufferFactory().wrap(new byte[actual]))));
        return e.mutate().principal(Mono.just(new JwtAuthenticationToken(Jwt.withTokenValue("test").header("alg","RS256")
                .claim("iss","https://issuer.test").subject("subject").build()))).build();
    }
    @Test void actualBytesWinOverUnderreportedContentLength(){
        var e=exchange(1L,1025);var called=new AtomicBoolean();
        new GatewayAbuseFilter(GatewayCanonicalIpTest.policy()).filter(e,next->{called.set(true);return Mono.empty();}).block();
        assertEquals(413,e.getResponse().getStatusCode().value());assertFalse(called.get());
    }
    @Test void unknownLengthIsBoundedToo(){
        var e=exchange(null,1025);
        new GatewayAbuseFilter(GatewayCanonicalIpTest.policy()).filter(e,next->{fail("body must stop");return Mono.empty();}).block();
        assertEquals(413,e.getResponse().getStatusCode().value());
    }
    @Test void slowBodyTimesOutWithoutReachingUpstream(){
        StepVerifier.withVirtualTime(()->{
            var e=exchange(null,0).mutate().request(new org.springframework.http.server.reactive.ServerHttpRequestDecorator(exchange(null,0).getRequest()){
                @Override public Flux<org.springframework.core.io.buffer.DataBuffer> getBody(){return Flux.never();}
            }).build();
            return new GatewayAbuseFilter(GatewayCanonicalIpTest.policy()).filter(e,next->{fail("slow body must stop");return Mono.empty();})
                    .then(Mono.fromRunnable(()->assertEquals(408,e.getResponse().getStatusCode().value())));
        }).thenAwait(Duration.ofSeconds(2)).verifyComplete();
    }
    @Test void cancellationReleasesConcurrencyAndRequestDeadlineIsBounded(){
        var filter=new GatewayAbuseFilter(GatewayCanonicalIpTest.policy());
        var a=filter.filter(exchange(null,0),next->Mono.never()).subscribe();
        var b=filter.filter(exchange(null,0),next->Mono.never()).subscribe();
        var rejected=exchange(null,0);filter.filter(rejected,next->{fail("concurrency full");return Mono.empty();}).block();
        assertEquals(429,rejected.getResponse().getStatusCode().value());a.dispose();b.dispose();
        // A fresh filter avoids rate depletion in this separate deadline assertion.
        StepVerifier.withVirtualTime(()->{
            var e=exchange(null,0);
            return new GatewayAbuseFilter(GatewayCanonicalIpTest.policy()).filter(e,next->Mono.never())
                    .then(Mono.fromRunnable(()->assertEquals(408,e.getResponse().getStatusCode().value())));
        }).thenAwait(Duration.ofSeconds(4)).verifyComplete();
        var next=exchange(null,0);filter.filter(next,e->Mono.empty()).block();assertNull(next.getResponse().getStatusCode());
    }
}
