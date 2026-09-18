package com.zerotrust.risk.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.risk.security.RiskJwtAuthenticationConverter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;
import java.util.Map;

@Configuration
public class RiskApiSecurityConfig {
    @Bean
    public JwtDecoder riskJwtDecoder(RiskApiSecurityProperties properties) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(properties.jwkSetUri().toString()).build();
        OAuth2TokenValidator<Jwt> audienceAndExpiry = jwt ->
                jwt.getExpiresAt() != null && jwt.getAudience() != null
                        && jwt.getAudience().contains(properties.audience())
                        ? OAuth2TokenValidatorResult.success()
                        : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token"));
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(properties.issuerUri().toString()), audienceAndExpiry));
        return decoder;
    }

    @Bean
    public SecurityFilterChain riskSecurityFilterChain(
            HttpSecurity http, RiskApiSecurityProperties properties, ObjectMapper mapper) throws Exception {
        AuthenticationEntryPoint unauthorized = (request, response, exception) -> {
            response.setHeader("WWW-Authenticate", "Bearer");
            writeError(mapper, request, response, 401, "UNAUTHORIZED");
        };
        AccessDeniedHandler forbidden = (request, response, exception) ->
                writeError(mapper, request, response, 403, "FORBIDDEN");
        http.csrf(csrf -> csrf.disable())
                .cors(cors -> cors.disable())
                .requestCache(cache -> cache.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers(HttpMethod.GET, "/actuator/health").permitAll()
                        .requestMatchers(HttpMethod.POST, "/internal/v1/risk/evaluations")
                        .access((authentication, context) -> new AuthorizationDecision(
                                isAuthorizedServiceToken(
                                        authentication.get(),
                                        properties,
                                        RiskJwtAuthenticationConverter.EVALUATE_AUTHORITY
                                )
                        ))
                        .requestMatchers(HttpMethod.POST, "/internal/v1/trusted-devices")
                        .access((authentication, context) -> new AuthorizationDecision(
                                isAuthorizedServiceToken(
                                        authentication.get(),
                                        properties,
                                        RiskJwtAuthenticationConverter.DEVICE_WRITE_AUTHORITY
                                )
                        ))
                        .requestMatchers(HttpMethod.POST, "/internal/v1/authentication-failures")
                        .access((authentication, context) -> new AuthorizationDecision(
                                isAuthorizedServiceToken(
                                        authentication.get(),
                                        properties,
                                        RiskJwtAuthenticationConverter.EVENTS_WRITE_AUTHORITY
                                )
                        ))
                        .requestMatchers(HttpMethod.POST, "/internal/v1/authentication-successes")
                        .access((authentication, context) -> new AuthorizationDecision(
                                isAuthorizedServiceToken(
                                        authentication.get(),
                                        properties,
                                        RiskJwtAuthenticationConverter.EVENTS_WRITE_AUTHORITY
                                )
                        ))
                        .anyRequest().denyAll())
                .oauth2ResourceServer(resource -> resource
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(new RiskJwtAuthenticationConverter(properties.audience())))
                        .authenticationEntryPoint(unauthorized).accessDeniedHandler(forbidden))
                .exceptionHandling(errors -> errors.authenticationEntryPoint(unauthorized).accessDeniedHandler(forbidden));
        // Refuse insecure requests instead of redirecting a POST carrying credentials/context.
        if (properties.requireHttps()) {
            http.addFilterBefore(new org.springframework.web.filter.OncePerRequestFilter() {
                @Override
                protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                        jakarta.servlet.FilterChain chain) throws jakarta.servlet.ServletException, IOException {
                    if (!request.isSecure()) {
                        writeError(mapper, request, response, 403, "HTTPS_REQUIRED");
                        return;
                    }
                    chain.doFilter(request, response);
                }
            }, org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter.class);
        }
        return http.build();
    }

    private static boolean isAuthorizedServiceToken(
            Authentication authentication,
            RiskApiSecurityProperties properties,
            String requiredAuthority
    ) {
        return authentication instanceof JwtAuthenticationToken token
                && properties.allowedClientId().equals(token.getToken().getClaims().get("azp"))
                && token.getAuthorities().stream().anyMatch(
                        authority -> requiredAuthority.equals(authority.getAuthority())
                );
    }

    private static void writeError(ObjectMapper mapper, HttpServletRequest request,
            HttpServletResponse response, int status, String error) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        mapper.writeValue(response.getOutputStream(), Map.of(
                "status", status, "error", error, "path", request.getRequestURI()));
    }
}
