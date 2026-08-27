package com.zerotrust.zerotrust.controller;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.web.csrf.DefaultCsrfToken;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AuthControllerTest {
    private final AuthController authController = new AuthController();

    @Test
    void returnsUnauthenticatedSessionWithoutLogin() {
        var response = authController.getSession(null);

        assertThat(response.authenticated()).isFalse();
        assertThat(response.username()).isNull();
        assertThat(response.roles()).isEmpty();
    }

    @Test
    void returnsOidcUsernameAndApplicationRoles() {
        Instant issuedAt = Instant.now();
        OidcIdToken idToken = new OidcIdToken(
                "id-token",
                issuedAt,
                issuedAt.plusSeconds(300),
                Map.of(
                        "sub", "user-id",
                        "preferred_username", "student01"));
        DefaultOidcUser oidcUser = new DefaultOidcUser(
                List.of(
                        new SimpleGrantedAuthority("OIDC_USER"),
                        new SimpleGrantedAuthority("ROLE_STUDENT")),
                idToken,
                "preferred_username");
        OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(
                oidcUser,
                oidcUser.getAuthorities(),
                "keycloak");

        var response = authController.getSession(authentication);

        assertThat(response.authenticated()).isTrue();
        assertThat(response.username()).isEqualTo("student01");
        assertThat(response.roles()).containsExactly("STUDENT");
    }

    @Test
    void returnsCsrfTokenContractExpectedByFrontend() {
        DefaultCsrfToken token = new DefaultCsrfToken(
                "X-CSRF-TOKEN",
                "_csrf",
                "csrf-value");

        var response = authController.getCsrfToken(token);

        assertThat(response.token()).isEqualTo("csrf-value");
        assertThat(response.headerName()).isEqualTo("X-CSRF-TOKEN");
        assertThat(response.parameterName()).isEqualTo("_csrf");
    }
}
