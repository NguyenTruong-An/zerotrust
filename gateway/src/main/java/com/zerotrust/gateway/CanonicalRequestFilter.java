package com.zerotrust.gateway;

import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.*;
import reactor.core.publisher.Mono;
import java.util.*;
import java.util.regex.Pattern;

@Component
public class CanonicalRequestFilter implements WebFilter,Ordered {
    public static final String CLIENT_IP="zerotrust.canonical-client-ip";
    private static final Pattern OPERATOR_PATH = Pattern.compile(
            "(?:^|/)(?:internal|observatory|observation|risk-observation|risk-observatory(?:-[a-z0-9_-]+)?"
                    + "|risk-traces?|raw-traces?|presentation|\\.local-legacy|\\.local-demo)(?:/|$)",
            Pattern.CASE_INSENSITIVE);
    private final GatewayEdgePolicy policy;
    public CanonicalRequestFilter(){this(GatewayEdgePolicy.disabled());}
    @org.springframework.beans.factory.annotation.Autowired
    public CanonicalRequestFilter(GatewayEdgePolicy policy){this.policy=policy;}
    @Override public int getOrder() { return Ordered.HIGHEST_PRECEDENCE; }
    static boolean untrusted(String name) {
        String key=name.toLowerCase(Locale.ROOT);
        return key.equals("forwarded") || key.startsWith("x-forwarded-") || key.equals("x-real-ip") || key.equals("x-client-ip")
                || key.equals("true-client-ip") || key.equals("x-role")
                || key.equals("x-roles") || key.equals("x-user") || key.equals("x-user-id") || key.equals("x-subject")
                || key.startsWith("x-auth-request-") || key.equals("x-original-url") || key.equals("x-rewrite-url");
    }
    @Override public Mono<Void> filter(ServerWebExchange exchange,WebFilterChain chain) {
        if(policy.enabled()){
            var socket=exchange.getRequest().getRemoteAddress();
            if(socket==null || socket.getAddress()==null || policy.proxies().stream().noneMatch(p->p.contains(socket.getAddress())))
                return GatewayAbuseFilter.error(exchange,403,0);
            var forwarded=exchange.getRequest().getHeaders().get("X-Forwarded-For");
            if(forwarded==null || forwarded.size()!=1)return GatewayAbuseFilter.error(exchange,400,0);
            try{exchange.getAttributes().put(CLIENT_IP,ClientIp.normalize(forwarded.get(0)));}
            catch(IllegalArgumentException e){return GatewayAbuseFilter.error(exchange,400,0);}
        }
        String path=exchange.getRequest().getURI().getRawPath().toLowerCase(Locale.ROOT);
        if (path.contains("%2f") || path.contains("%5c") || path.contains("%2e") || path.contains("%25")
                || path.contains("\\") || path.contains("//") || path.contains(";") || path.matches(".*(?:^|/)\\.\\.?(?:/|$).*")) {
            exchange.getResponse().setStatusCode(HttpStatus.BAD_REQUEST);return exchange.getResponse().setComplete();
        }
        if (policy.enabled() && OPERATOR_PATH.matcher(exchange.getRequest().getURI().getPath()).find()) {
            exchange.getResponse().setStatusCode(HttpStatus.NOT_FOUND);
            return exchange.getResponse().setComplete();
        }
        String correlation=UUID.randomUUID().toString();
        var request=exchange.getRequest().mutate().headers(h -> {
            new ArrayList<>(h.headerNames()).stream().filter(CanonicalRequestFilter::untrusted).forEach(h::remove);
            h.set("X-Correlation-ID",correlation);
        }).build();
        exchange.getResponse().getHeaders().set("X-Correlation-ID",correlation);
        return chain.filter(exchange.mutate().request(request).build());
    }
}
