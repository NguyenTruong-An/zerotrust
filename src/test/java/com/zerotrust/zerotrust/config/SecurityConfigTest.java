package com.zerotrust.zerotrust.config;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityConfigTest {

    private final SecurityConfig securityConfig = new SecurityConfig();

    @Test
    void mapsKeycloakRealmRolesToSpringRoles() {
        OidcIdToken idToken = idToken(Map.of(
                "realm_access", Map.of("roles", List.of("admin", "student"))));
        OidcUserAuthority oidcAuthority = new OidcUserAuthority(idToken);

        var authorities = securityConfig.keycloakAuthoritiesMapper().mapAuthorities(List.of(
                oidcAuthority,
                new SimpleGrantedAuthority("SCOPE_users.read")));

        assertThat(authorities)
                .extracting("authority")
                .containsExactlyInAnyOrder(
                        "OIDC_USER",
                        "SCOPE_users.read",
                        "ROLE_ADMIN",
                        "ROLE_STUDENT");
    }

    @Test
    void handlesIdTokensWithoutRealmRoles() {
        OidcUserAuthority oidcAuthority = new OidcUserAuthority(idToken(Map.of()));

        var authorities = securityConfig.keycloakAuthoritiesMapper()
                .mapAuthorities(List.of(oidcAuthority));

        assertThat(authorities)
                .extracting("authority")
                .containsExactly("OIDC_USER");
    }

    @Test
    void addsPkceToConfidentialClientAuthorizationRequest() {
        ClientRegistration registration = ClientRegistration
                .withRegistrationId("keycloak")
                .clientId("zerotrust-bff")
                .clientSecret("secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope("openid")
                .authorizationUri("http://localhost:8180/realms/DoAn/protocol/openid-connect/auth")
                .tokenUri("http://localhost:8180/realms/DoAn/protocol/openid-connect/token")
                .jwkSetUri("http://localhost:8180/realms/DoAn/protocol/openid-connect/certs")
                .userInfoUri("http://localhost:8180/realms/DoAn/protocol/openid-connect/userinfo")
                .userNameAttributeName("sub")
                .clientName("Keycloak")
                .build();
        var resolver = securityConfig.authorizationRequestResolver(
                new InMemoryClientRegistrationRepository(registration));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("localhost");
        request.setServerPort(8080);
        request.setRequestURI("/oauth2/authorization/keycloak");

        var authorizationRequest = resolver.resolve(request, "keycloak");

        assertThat(authorizationRequest).isNotNull();
        assertThat(authorizationRequest.getAdditionalParameters())
                .containsEntry("code_challenge_method", "S256")
                .containsKey("code_challenge");
        assertThat(authorizationRequest.getAttributes()).containsKey("code_verifier");
    }

    private OidcIdToken idToken(Map<String, Object> additionalClaims) {
        Instant issuedAt = Instant.now();
        Map<String, Object> claims = new java.util.HashMap<>(additionalClaims);
        claims.put("sub", "user-id");
        return new OidcIdToken(
                "token",
                issuedAt,
                issuedAt.plusSeconds(300),
                claims);
    }
}
