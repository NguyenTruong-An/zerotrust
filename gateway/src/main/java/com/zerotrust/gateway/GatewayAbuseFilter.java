package com.zerotrust.gateway;

import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.*;
import org.springframework.http.*;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.*;
import reactor.core.publisher.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.concurrent.TimeoutException;

@Component
final class GatewayAbuseFilter implements WebFilter, Ordered {
    private final GatewayEdgePolicy policy;
    private final BoundedAdmissions admissions;
    GatewayAbuseFilter(GatewayEdgePolicy policy){this(policy,System::nanoTime);}
    @org.springframework.beans.factory.annotation.Autowired
    GatewayAbuseFilter(GatewayEdgePolicy policy,
            @org.springframework.beans.factory.annotation.Qualifier("gatewayAdmissionClock") java.util.function.LongSupplier clock){
        this.policy=policy;admissions=new BoundedAdmissions(policy,clock);
    }
    @Override public int getOrder(){return 0;} // After Security's authorization; no new authentication source.
    @Override public Mono<Void> filter(ServerWebExchange exchange,WebFilterChain chain){
        if(!policy.enabled())return chain.filter(exchange);
        boolean api=exchange.getRequest().getPath().value().equals("/api") || exchange.getRequest().getPath().value().startsWith("/api/");
        return exchange.getPrincipal().map(p->p instanceof JwtAuthenticationToken jwt && jwt.getToken().getSubject()!=null
                ? "subject:"+hash(jwt.getToken().getIssuer()+"\0"+jwt.getToken().getSubject()) : "anonymous")
                .defaultIfEmpty("anonymous").flatMap(subject->Mono.defer(()->{
                    if(api && subject.equals("anonymous"))return error(exchange,401,0);
                    String key=api?subject:"static:"+hash(exchange.getAttributeOrDefault(CanonicalRequestFilter.CLIENT_IP,"unknown"));
                    var admission=admissions.acquire(key,api);
                    if(!admission.accepted())return error(exchange,429,admission.retryAfter());
                    return boundedBody(exchange,chain,api?policy.apiBytes():policy.staticBytes())
                            .timeout(policy.requestTimeout())
                            .onErrorResume(DataBufferLimitException.class,e->error(exchange,413,0))
                            .onErrorResume(TimeoutException.class,e->error(exchange,408,0))
                            .doFinally(signal->admission.release().run());
                }));
    }
    private Mono<Void> boundedBody(ServerWebExchange exchange,WebFilterChain chain,int max){
        if(exchange.getRequest().getHeaders().getContentLength()>max)return error(exchange,413,0);
        return DataBufferUtils.join(exchange.getRequest().getBody(),max)
                .timeout(policy.bodyTimeout()).map(buffer->{
                    byte[] bytes=new byte[buffer.readableByteCount()];buffer.read(bytes);DataBufferUtils.release(buffer);return bytes;
                }).defaultIfEmpty(new byte[0]).flatMap(bytes->{
                    var request=new ServerHttpRequestDecorator(exchange.getRequest()){
                        @Override public HttpHeaders getHeaders(){
                            HttpHeaders headers=new HttpHeaders();headers.addAll(super.getHeaders());
                            headers.remove(HttpHeaders.TRANSFER_ENCODING);headers.setContentLength(bytes.length);return headers;
                        }
                        @Override public Flux<DataBuffer> getBody(){return Flux.defer(()->Flux.just(exchange.getResponse().bufferFactory().wrap(bytes)));}
                    };
                    return chain.filter(exchange.mutate().request(request).build());
                });
    }
    static Mono<Void> error(ServerWebExchange exchange,int status,int retry){
        if(exchange.getResponse().isCommitted())return Mono.error(new IllegalStateException("Bounded Gateway request failed after response commit"));
        exchange.getResponse().setStatusCode(HttpStatusCode.valueOf(status));
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        exchange.getResponse().getHeaders().setCacheControl("no-store");
        if(retry>0)exchange.getResponse().getHeaders().set(HttpHeaders.RETRY_AFTER,Integer.toString(retry));
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(
                ("{\"status\":"+status+",\"error\":\"REQUEST_REJECTED\"}").getBytes(StandardCharsets.UTF_8))));
    }
    private static String hash(String value){
        try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));}
        catch(java.security.NoSuchAlgorithmException e){throw new IllegalStateException("Required digest unavailable");}
    }
}
