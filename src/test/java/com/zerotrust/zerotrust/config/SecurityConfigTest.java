package com.zerotrust.zerotrust.config;

import com.zerotrust.zerotrust.exception.CustomAuthenticationEntryPoint;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class SecurityConfigTest {

    private final SecurityConfig securityConfig =
            new SecurityConfig(mock(CustomAuthenticationEntryPoint.class));

    @Test
    void mapsKeycloakRealmRolesToSpringRoles() {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .subject("user-id")
                .claim("scope", "users.read")
                .claim("realm_access", Map.of("roles", List.of("admin", "student")))
                .build();

        var authentication = securityConfig.keycloakJwtAuthenticationConverter().convert(jwt);

        assertThat(authentication).isNotNull();
        assertThat(authentication.getAuthorities())
                .extracting("authority")
                .containsExactlyInAnyOrder("SCOPE_users.read", "ROLE_ADMIN", "ROLE_STUDENT");
    }

    @Test
    void handlesTokensWithoutRealmRoles() {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .subject("user-id")
                .build();

        var authentication = securityConfig.keycloakJwtAuthenticationConverter().convert(jwt);

        assertThat(authentication).isNotNull();
        assertThat(authentication.getAuthorities()).isEmpty();
    }
}
