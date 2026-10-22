package com.zerotrust.gateway;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.http.*;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter;
import org.springframework.web.cors.*;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

@Configuration @EnableWebFluxSecurity
public class GatewaySecurityConfig {
    @Bean
    ReactiveJwtDecoder jwtDecoder(@Value("${app.security.jwt.issuer}") String issuer,
            @Value("${app.security.jwt.jwks}") String jwks,@Value("${app.security.jwt.audience}") String audience) {
        NimbusReactiveJwtDecoder decoder=NimbusReactiveJwtDecoder.withJwkSetUri(jwks).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer),
                new JwtClaimValidator<Instant>(JwtClaimNames.EXP,Objects::nonNull),
                jwt -> jwt.getAudience()!=null && jwt.getAudience().contains(audience)
                        ? OAuth2TokenValidatorResult.success() : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token","Required audience missing",null))));
        return decoder;
    }
    @Bean
    SecurityWebFilterChain security(ServerHttpSecurity http,@Value("${app.security.cors.origins}") String origins) {
        ReactiveJwtAuthenticationConverter converter=new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Object access=jwt.getClaims().get("realm_access");
            Object roles=access instanceof Map<?,?> map ? map.get("roles") : null;
            if (!(roles instanceof Collection<?> values)) return Flux.empty();
            return Flux.fromIterable(values).filter(String.class::isInstance).cast(String.class)
                    .map(role -> new SimpleGrantedAuthority("ROLE_"+role.toUpperCase(Locale.ROOT)));
        });
        CorsConfiguration cors=new CorsConfiguration();cors.setAllowedOrigins(Arrays.stream(origins.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList());
        cors.setAllowedMethods(List.of("GET","POST","PUT","PATCH","DELETE","OPTIONS"));
        cors.setAllowedHeaders(List.of("Authorization","Content-Type","Accept"));cors.setAllowCredentials(false);cors.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource corsSource=new UrlBasedCorsConfigurationSource();corsSource.registerCorsConfiguration("/api/**",cors);
        return http.csrf(ServerHttpSecurity.CsrfSpec::disable).cors(c -> c.configurationSource(corsSource))
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .requestCache(c -> c.requestCache(NoOpServerRequestCache.getInstance()))
                .headers(h -> h.frameOptions(f -> f.mode(XFrameOptionsServerHttpHeadersWriter.Mode.SAMEORIGIN)))
                .authorizeExchange(a -> a.pathMatchers(HttpMethod.OPTIONS,"/**").permitAll()
                        .pathMatchers("/api/admin/**").hasRole("ADMIN")
                        .pathMatchers("/api/teachers/**").hasRole("TEACHER")
                        .pathMatchers("/api/students/**").hasRole("STUDENT")
                        .pathMatchers("/api","/api/**").authenticated().anyExchange().permitAll())
                .oauth2ResourceServer(o -> o.jwt(j -> j.jwtAuthenticationConverter(converter))
                        .authenticationEntryPoint((e,x) -> error(e,HttpStatus.UNAUTHORIZED))
                        .accessDeniedHandler((e,x) -> error(e,HttpStatus.FORBIDDEN)))
                .exceptionHandling(e -> e.authenticationEntryPoint((x,t) -> error(x,HttpStatus.UNAUTHORIZED))
                        .accessDeniedHandler((x,t) -> error(x,HttpStatus.FORBIDDEN))).build();
    }
    private Mono<Void> error(ServerWebExchange exchange,HttpStatus status) {
        exchange.getResponse().setStatusCode(status);exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        exchange.getResponse().getHeaders().setCacheControl("no-store");
        byte[] body=("{\"status\":"+status.value()+",\"error\":\""+status.name()+"\"}").getBytes(StandardCharsets.UTF_8);
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(body)));
    }
}
