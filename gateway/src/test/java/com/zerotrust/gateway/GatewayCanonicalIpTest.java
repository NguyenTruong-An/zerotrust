package com.zerotrust.gateway;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.jupiter.api.Assertions.*;

class GatewayCanonicalIpTest {
    static GatewayEdgePolicy policy(){return new GatewayEdgePolicy(true,List.of(ClientIp.Cidr.parse("10.20.0.0/24"),ClientIp.Cidr.parse("2001:db8:1::/64")),
            1024,128,1,3,10,20,4,2,4,16,java.time.Duration.ofSeconds(60),java.time.Duration.ofSeconds(1),java.time.Duration.ofSeconds(3));}
    @ParameterizedTest @CsvSource({"001.002.003.004,1.2.3.4","2001:DB8::1,2001:db8:0:0:0:0:0:1","2001:db8:0:0:0:0:c000:201,2001:db8:0:0:0:0:c000:201","2001:db8::192.0.2.1,2001:db8:0:0:0:0:c000:201"})
    void normalizationMatchesRisk(String input,String expected){assertEquals(expected,ClientIp.normalize(input));}
    @ParameterizedTest @ValueSource(strings={"localhost","1.2.3","1.2.3.999","::ffff:192.0.2.1","fe80::1%eth0","[2001:db8::1]","1.2.3.4:443","1.2.3.4, 5.6.7.8"})
    void malformedLiteralsAndProxyChainsFail(String value){assertThrows(IllegalArgumentException.class,()->ClientIp.normalize(value));}
    @Test void trustedSocketUsesOnlyTheSingleCanonicalXff(){
        var e=MockServerWebExchange.from(MockServerHttpRequest.get("/api/students/me").remoteAddress(new InetSocketAddress("10.20.0.3",1234))
                .header("X-Forwarded-For","2001:DB8::1").header("Forwarded","for=evil").header("X-Real-IP","9.9.9.9")
                .header("X-Forwarded-Proto","http").header("X-Forwarded-Host","evil").header("X-Role","ADMIN"));
        new CanonicalRequestFilter(policy()).filter(e,next->{
            assertEquals("2001:db8:0:0:0:0:0:1",next.getAttribute(CanonicalRequestFilter.CLIENT_IP));
            for(String key:List.of("Forwarded","X-Real-IP","X-Forwarded-For","X-Forwarded-Host","X-Forwarded-Proto","X-Role"))assertNull(next.getRequest().getHeaders().getFirst(key));
            return Mono.empty();
        }).block();
    }
    @ParameterizedTest @ValueSource(strings={"192.0.2.1","10.21.0.1","2001:db8:2::1"})
    void directUntrustedSocketCannotBecomeTrustedViaHeaders(String peer){
        var e=MockServerWebExchange.from(MockServerHttpRequest.get("/api/admin/users").remoteAddress(new InetSocketAddress(ClientIp.parse(peer),1234))
                .header("X-Forwarded-For","10.20.0.3").header("X-Role","ADMIN"));AtomicBoolean reached=new AtomicBoolean();
        new CanonicalRequestFilter(policy()).filter(e,next->{reached.set(true);return Mono.empty();}).block();
        assertEquals(HttpStatus.FORBIDDEN,e.getResponse().getStatusCode());assertFalse(reached.get());
    }
    @ParameterizedTest @ValueSource(strings={"198.51.100.1,10.20.0.3","unknown","for=198.51.100.1",""})
    void trustedPeerCannotForwardAnUnreviewedChain(String value){
        var e=MockServerWebExchange.from(MockServerHttpRequest.get("/").remoteAddress(new InetSocketAddress("10.20.0.3",1234)).header("X-Forwarded-For",value));
        new CanonicalRequestFilter(policy()).filter(e,next->{fail("invalid IP must stop");return Mono.empty();}).block();
        assertEquals(HttpStatus.BAD_REQUEST,e.getResponse().getStatusCode());
    }
    @Test void ipv6TrustedProxyAndCidrBoundary(){assertTrue(ClientIp.Cidr.parse("2001:db8:1::/64").contains(ClientIp.parse("2001:db8:1::a")));
        assertFalse(ClientIp.Cidr.parse("2001:db8:1::/64").contains(ClientIp.parse("2001:db8:2::a")));}
}
