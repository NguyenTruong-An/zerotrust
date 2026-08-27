package com.zerotrust.zerotrust.security;

import com.zerotrust.zerotrust.exception.CustomAuthenticationEntryPoint;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;

public class OAuth2SessionRefreshFilter extends OncePerRequestFilter {
    private final OAuth2AuthorizedClientManager authorizedClientManager;
    private final CustomAuthenticationEntryPoint authenticationEntryPoint;
    private final CookieClearingLogoutHandler cookieClearingLogoutHandler =
            new CookieClearingLogoutHandler("zerotrust-session", "__Host-session");

    public OAuth2SessionRefreshFilter(
            OAuth2AuthorizedClientManager authorizedClientManager,
            CustomAuthenticationEntryPoint authenticationEntryPoint
    ) {
        this.authorizedClientManager = authorizedClientManager;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof OAuth2AuthenticationToken oauth2Authentication)
                || !authentication.isAuthenticated()) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                    .withClientRegistrationId(
                            oauth2Authentication.getAuthorizedClientRegistrationId())
                    .principal(oauth2Authentication)
                    .attribute(HttpServletRequest.class.getName(), request)
                    .attribute(HttpServletResponse.class.getName(), response)
                    .build();

            OAuth2AuthorizedClient authorizedClient =
                    authorizedClientManager.authorize(authorizeRequest);
            if (authorizedClient == null || isExpired(authorizedClient)) {
                endInvalidSession(request, response, authentication, null);
                return;
            }
        } catch (OAuth2AuthorizationException exception) {
            endInvalidSession(request, response, authentication, exception);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean isExpired(OAuth2AuthorizedClient authorizedClient) {
        Instant expiresAt = authorizedClient.getAccessToken().getExpiresAt();
        return expiresAt != null && expiresAt.isBefore(Instant.now());
    }

    private void endInvalidSession(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication,
            Exception cause
    ) throws IOException {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.clearContext();
        cookieClearingLogoutHandler.logout(request, response, authentication);

        authenticationEntryPoint.commence(
                request,
                response,
                new InsufficientAuthenticationException(
                        "The Keycloak session is no longer valid",
                        cause));
    }
}
