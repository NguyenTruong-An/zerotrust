package com.zerotrust.gateway;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.*;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.cloud.gateway.filter.headers.HttpHeadersFilter;
import org.springframework.context.annotation.*;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.web.server.ServerWebExchange;
import java.util.*;

@Configuration
public class GatewayRoutesConfig {
    @Bean RouteLocator routes(RouteLocatorBuilder builder,@Value("${app.routes.backend}") String backend,
            @Value("${app.routes.frontend}") String frontend) {
        return builder.routes()
                .route("school-api",r -> r.path("/api","/api/**").filters(f -> f.removeRequestHeader("Cookie")
                        .setResponseHeader("Cache-Control","no-store")
                        .dedupeResponseHeader("Access-Control-Allow-Origin Access-Control-Allow-Credentials","RETAIN_FIRST")).uri(backend))
                .route("portal",r -> r.path("/**").filters(f -> f.removeRequestHeader("Authorization").removeRequestHeader("Cookie")).uri(frontend)).build();
    }
    @Bean HttpHeadersFilter outgoingHeaderBoundary() { return new OutgoingHeaders(); }
    static final class OutgoingHeaders implements HttpHeadersFilter,Ordered {
        @Override public int getOrder() { return 1000; }
        @Override public HttpHeaders filter(HttpHeaders input,ServerWebExchange exchange) {
            HttpHeaders clean=new HttpHeaders();clean.addAll(input);
            new ArrayList<>(clean.keySet()).stream().filter(CanonicalRequestFilter::untrusted).forEach(clean::remove);
            return clean;
        }
    }
}
