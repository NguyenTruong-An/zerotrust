package com.zerotrust.zerotrust.config;

import com.zerotrust.zerotrust.security.KeycloakJwtAuthenticationConverter;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityConfigTest {
    private final KeycloakJwtAuthenticationConverter converter =
            new KeycloakJwtAuthenticationConverter();

    @Test
    void mapsKeycloakRealmRolesAndScopesToSpringAuthorities() {
        Jwt jwt = jwt(Map.of(
                "preferred_username", "admin01",
                "scope", "openid profile",
                "realm_access", Map.of("roles", List.of("admin", "student"))),
                List.of("zerotrust-api"));

        var authentication = converter.convert(jwt);

        assertThat(authentication).isNotNull();
        assertThat(authentication.getName()).isEqualTo("admin01");
        assertThat(authentication.getAuthorities())
                .extracting("authority")
                .containsExactlyInAnyOrder(
                        "SCOPE_openid",
                        "SCOPE_profile",
                        "ROLE_ADMIN",
                        "ROLE_STUDENT");
    }

    @Test
    void handlesJwtWithoutRealmRoles() {
        var authentication = converter.convert(jwt(Map.of(), List.of("zerotrust-api")));

        assertThat(authentication).isNotNull();
        assertThat(authentication.getAuthorities()).isEmpty();
    }

    @Test
    void validatesRequiredAudience() {
        JwtAudienceValidator validator = new JwtAudienceValidator("zerotrust-api");

        assertThat(validator.validate(jwt(Map.of(), List.of("zerotrust-api"))).hasErrors())
                .isFalse();
        assertThat(validator.validate(jwt(Map.of(), List.of("account"))).hasErrors())
                .isTrue();
    }

    private Jwt jwt(Map<String, Object> additionalClaims, List<String> audience) {
        Instant issuedAt = Instant.now();
        Jwt.Builder builder = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("00000000-0000-4000-8000-000000000001")
                .issuedAt(issuedAt)
                .expiresAt(issuedAt.plusSeconds(300))
                .audience(audience);
        additionalClaims.forEach(builder::claim);
        return builder.build();
    }
}
