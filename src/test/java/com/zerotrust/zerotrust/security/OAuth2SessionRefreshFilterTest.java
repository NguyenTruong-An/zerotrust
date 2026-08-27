package com.zerotrust.zerotrust.security;

import com.zerotrust.zerotrust.exception.CustomAuthenticationEntryPoint;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OAuth2SessionRefreshFilterTest {

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void keepsSessionWhenAuthorizedClientIsValid() throws Exception {
        OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
        CustomAuthenticationEntryPoint entryPoint = mock(CustomAuthenticationEntryPoint.class);
        OAuth2AuthorizedClient authorizedClient = authorizedClientExpiringAt(
                Instant.now().plusSeconds(300));
        when(manager.authorize(any())).thenReturn(authorizedClient);
        SecurityContextHolder.getContext().setAuthentication(authentication());
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        new OAuth2SessionRefreshFilter(manager, entryPoint)
                .doFilter(request, response, filterChain);

        assertThat(filterChain.getRequest()).isSameAs(request);
        verify(entryPoint, never()).commence(any(), any(), any());
    }

    @Test
    void invalidatesSessionWhenRefreshCannotProduceAValidAccessToken() throws Exception {
        OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
        CustomAuthenticationEntryPoint entryPoint = mock(CustomAuthenticationEntryPoint.class);
        OAuth2AuthorizedClient expiredClient = authorizedClientExpiringAt(
                Instant.now().minusSeconds(1));
        when(manager.authorize(any())).thenReturn(expiredClient);
        SecurityContextHolder.getContext().setAuthentication(authentication());
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = (MockHttpSession) request.getSession();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        new OAuth2SessionRefreshFilter(manager, entryPoint)
                .doFilter(request, response, filterChain);

        assertThat(session.isInvalid()).isTrue();
        assertThat(filterChain.getRequest()).isNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(entryPoint).commence(any(), any(), any());
    }

    private OAuth2AuthenticationToken authentication() {
        Instant now = Instant.now();
        OidcIdToken idToken = new OidcIdToken(
                "id-token",
                now,
                now.plusSeconds(300),
                Map.of("sub", "user-id", "preferred_username", "student01"));
        DefaultOidcUser user = new DefaultOidcUser(
                List.of(new SimpleGrantedAuthority("ROLE_STUDENT")),
                idToken,
                "preferred_username");
        return new OAuth2AuthenticationToken(user, user.getAuthorities(), "keycloak");
    }

    private OAuth2AuthorizedClient authorizedClientExpiringAt(Instant expiresAt) {
        OAuth2AuthorizedClient authorizedClient = mock(OAuth2AuthorizedClient.class);
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "access-token",
                Instant.now().minusSeconds(30),
                expiresAt);
        when(authorizedClient.getAccessToken()).thenReturn(accessToken);
        return authorizedClient;
    }
}
