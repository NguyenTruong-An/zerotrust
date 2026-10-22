package com.zerotrust.gateway;

import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.*;
import reactor.core.publisher.Mono;
import java.util.*;

@Component
public class CanonicalRequestFilter implements WebFilter,Ordered {
    @Override public int getOrder() { return Ordered.HIGHEST_PRECEDENCE; }
    static boolean untrusted(String name) {
        String key=name.toLowerCase(Locale.ROOT);
        return key.equals("forwarded") || key.startsWith("x-forwarded-") || key.equals("x-role")
                || key.equals("x-roles") || key.equals("x-user") || key.equals("x-user-id") || key.equals("x-subject")
                || key.startsWith("x-auth-request-") || key.equals("x-original-url") || key.equals("x-rewrite-url");
    }
    @Override public Mono<Void> filter(ServerWebExchange exchange,WebFilterChain chain) {
        String path=exchange.getRequest().getURI().getRawPath().toLowerCase(Locale.ROOT);
        if (path.contains("%2f") || path.contains("%5c") || path.contains("%2e") || path.contains("%25")
                || path.contains("\\") || path.contains("//") || path.contains(";") || path.matches(".*(?:^|/)\\.\\.?(?:/|$).*")) {
            exchange.getResponse().setStatusCode(HttpStatus.BAD_REQUEST);return exchange.getResponse().setComplete();
        }
        String correlation=UUID.randomUUID().toString();
        var request=exchange.getRequest().mutate().headers(h -> {
            new ArrayList<>(h.keySet()).stream().filter(CanonicalRequestFilter::untrusted).forEach(h::remove);
            h.set("X-Correlation-ID",correlation);
        }).build();
        exchange.getResponse().getHeaders().set("X-Correlation-ID",correlation);
        return chain.filter(exchange.mutate().request(request).build());
    }
}
