package com.zerotrust.risk.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Accept only supported roles of the Risk API, never realm or other client roles. */
public final class RiskJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    public static final String EVALUATE_AUTHORITY = "risk:evaluate";
    public static final String DEVICE_WRITE_AUTHORITY = "risk:device:write";
    public static final String EVENTS_WRITE_AUTHORITY = "risk:events:write";

    private static final Set<String> SUPPORTED_AUTHORITIES = Set.of(
            EVALUATE_AUTHORITY,
            DEVICE_WRITE_AUTHORITY,
            EVENTS_WRITE_AUTHORITY
    );

    private final String resourceClientId;

    public RiskJwtAuthenticationConverter(String resourceClientId) {
        this.resourceClientId = resourceClientId;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Object resources = jwt.getClaims().get("resource_access");
        Collection<?> roles = resources instanceof Map<?, ?> clients
                && clients.get(resourceClientId) instanceof Map<?, ?> resource
                && resource.get("roles") instanceof Collection<?> resourceRoles
                ? resourceRoles
                : List.of();

        List<SimpleGrantedAuthority> authorities = roles.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .filter(SUPPORTED_AUTHORITIES::contains)
                .distinct()
                .map(SimpleGrantedAuthority::new)
                .toList();
        return new JwtAuthenticationToken(jwt, authorities);
    }
}
