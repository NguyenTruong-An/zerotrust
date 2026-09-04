package com.zerotrust.zerotrust.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;

@Component
public class KeycloakJwtAuthenticationConverter
        implements Converter<Jwt, AbstractAuthenticationToken> {
    private static final String REALM_ACCESS_CLAIM = "realm_access";
    private static final String ROLES_CLAIM = "roles";

    private final JwtGrantedAuthoritiesConverter scopeConverter =
            new JwtGrantedAuthoritiesConverter();

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = new LinkedHashSet<>(
                scopeConverter.convert(jwt));
        addRealmRoles(jwt.getClaimAsMap(REALM_ACCESS_CLAIM), authorities);

        String preferredUsername = jwt.getClaimAsString("preferred_username");
        String principalName = preferredUsername == null || preferredUsername.isBlank()
                ? jwt.getSubject()
                : preferredUsername;
        return new JwtAuthenticationToken(jwt, authorities, principalName);
    }

    private void addRealmRoles(
            Map<String, Object> realmAccess,
            Collection<GrantedAuthority> authorities
    ) {
        if (realmAccess == null) {
            return;
        }

        Object rolesClaim = realmAccess.get(ROLES_CLAIM);
        if (!(rolesClaim instanceof Collection<?> roles)) {
            return;
        }

        roles.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .map(role -> role.toUpperCase(Locale.ROOT))
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .forEach(authorities::add);
    }
}
