package com.zerotrust.zerotrust.config;

import com.zerotrust.zerotrust.exception.CustomAuthenticationEntryPoint;
import com.zerotrust.zerotrust.security.OAuth2SessionRefreshFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

import java.util.Collection;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    private static final String REALM_ACCESS_CLAIM = "realm_access";
    private static final String ROLES_CLAIM = "roles";

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity httpSecurity,
            CustomAuthenticationEntryPoint customAuthenticationEntryPoint,
            OAuth2AuthorizationRequestResolver authorizationRequestResolver,
            OAuth2AuthorizedClientRepository authorizedClientRepository,
            OAuth2AuthorizedClientManager authorizedClientManager,
            GrantedAuthoritiesMapper keycloakAuthoritiesMapper,
            CsrfTokenRepository csrfTokenRepository,
            LogoutSuccessHandler oidcLogoutSuccessHandler,
            @Value("${app.security.login-success-uri:/}") String loginSuccessUri
    ) throws Exception {
        httpSecurity.authorizeHttpRequests(request -> request
                .requestMatchers(
                        "/",
                        "/index.html",
                        "/favicon.ico",
                        "/assets/**",
                        "/error",
                        "/oauth2/**",
                        "/login/**",
                        "/api/auth/session")
                .permitAll()
                .requestMatchers("/api/auth/csrf")
                .authenticated()
                .requestMatchers("/api/admin/**")
                .hasRole("ADMIN")
                .requestMatchers("/api/students/**")
                .hasRole("STUDENT")
                .anyRequest()
                .authenticated());

        httpSecurity.oauth2Login(oauth2 -> oauth2
                .authorizationEndpoint(endpoint -> endpoint
                        .authorizationRequestResolver(authorizationRequestResolver))
                .userInfoEndpoint(userInfo -> userInfo
                        .userAuthoritiesMapper(keycloakAuthoritiesMapper))
                .defaultSuccessUrl(loginSuccessUri, true));

        httpSecurity.oauth2Client(oauth2 -> oauth2
                .authorizedClientRepository(authorizedClientRepository));

        httpSecurity.csrf(csrf -> csrf
                .csrfTokenRepository(csrfTokenRepository));

        httpSecurity.sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));

        httpSecurity.exceptionHandling(exception -> exception
                .authenticationEntryPoint(customAuthenticationEntryPoint));

        httpSecurity.logout(logout -> logout
                .logoutUrl("/api/auth/logout")
                .logoutSuccessHandler(oidcLogoutSuccessHandler)
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("zerotrust-session", "__Host-session")
                .permitAll());

        httpSecurity.addFilterAfter(
                new OAuth2SessionRefreshFilter(
                        authorizedClientManager,
                        customAuthenticationEntryPoint),
                OAuth2LoginAuthenticationFilter.class);

        return httpSecurity.build();
    }

    @Bean
    public OAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository
    ) {
        DefaultOAuth2AuthorizationRequestResolver resolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository,
                        OAuth2AuthorizationRequestRedirectFilter
                                .DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
        resolver.setAuthorizationRequestCustomizer(
                OAuth2AuthorizationRequestCustomizers.withPkce());
        return resolver;
    }

    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository() {
        return new HttpSessionOAuth2AuthorizedClientRepository();
    }

    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository
    ) {
        OAuth2AuthorizedClientProvider authorizedClientProvider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        .refreshToken(refreshToken -> refreshToken
                                .clockSkew(Duration.ofSeconds(60)))
                        .build();
        DefaultOAuth2AuthorizedClientManager manager =
                new DefaultOAuth2AuthorizedClientManager(
                        clientRegistrationRepository,
                        authorizedClientRepository);
        manager.setAuthorizedClientProvider(authorizedClientProvider);
        return manager;
    }

    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setHeaderName("X-CSRF-TOKEN");
        return repository;
    }

    @Bean
    public LogoutSuccessHandler oidcLogoutSuccessHandler(
            ClientRegistrationRepository clientRegistrationRepository,
            @Value("${app.security.logout-success-path:/}") String logoutSuccessPath
    ) {
        OidcClientInitiatedLogoutSuccessHandler handler =
                new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        handler.setPostLogoutRedirectUri("{baseUrl}" + logoutSuccessPath);
        return handler;
    }

    @Bean
    public GrantedAuthoritiesMapper keycloakAuthoritiesMapper() {
        return authorities -> {
            Set<GrantedAuthority> mappedAuthorities = new LinkedHashSet<>(authorities);
            for (GrantedAuthority authority : authorities) {
                if (authority instanceof OidcUserAuthority oidcAuthority) {
                    addRealmRoles(oidcAuthority.getIdToken().getClaims(), mappedAuthorities);
                    if (oidcAuthority.getUserInfo() != null) {
                        addRealmRoles(oidcAuthority.getUserInfo().getClaims(), mappedAuthorities);
                    }
                } else if (authority instanceof OAuth2UserAuthority oauth2Authority) {
                    addRealmRoles(oauth2Authority.getAttributes(), mappedAuthorities);
                }
            }
            return mappedAuthorities;
        };
    }

    private void addRealmRoles(
            Map<String, Object> claims,
            Collection<GrantedAuthority> authorities
    ) {
        Object realmAccessClaim = claims.get(REALM_ACCESS_CLAIM);
        if (!(realmAccessClaim instanceof Map<?, ?> realmAccess)) {
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
