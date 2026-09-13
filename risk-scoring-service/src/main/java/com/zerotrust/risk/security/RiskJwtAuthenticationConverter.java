package com.zerotrust.risk.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;
import java.util.List;
import java.util.Map;

/** Accept only the evaluation role of the Risk API, never realm or other client roles. */
public final class RiskJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    public static final String EVALUATE_AUTHORITY = "risk:evaluate";
    private final String resourceClientId;

    public RiskJwtAuthenticationConverter(String resourceClientId) {
        this.resourceClientId = resourceClientId;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Object resources = jwt.getClaims().get("resource_access");
        boolean allowed = resources instanceof Map<?, ?> clients
                && clients.get(resourceClientId) instanceof Map<?, ?> resource
                && resource.get("roles") instanceof Collection<?> roles
                && roles.contains(EVALUATE_AUTHORITY);
        return new JwtAuthenticationToken(jwt, allowed
                ? List.of(new SimpleGrantedAuthority(EVALUATE_AUTHORITY)) : List.of());
    }
}
