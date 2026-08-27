package com.zerotrust.zerotrust.controller;

import com.zerotrust.zerotrust.config.SecurityConfig;
import com.zerotrust.zerotrust.exception.CustomAuthenticationEntryPoint;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@Import({SecurityConfig.class, CustomAuthenticationEntryPoint.class})
class AuthControllerSecurityTest {
    @Autowired
    private MockMvc mockMvc;
    @MockitoBean
    private ClientRegistrationRepository clientRegistrationRepository;

    @Test
    void reportsUnauthenticatedSessionWithoutRedirectingToKeycloak() throws Exception {
        mockMvc.perform(get("/api/auth/session"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticated").value(false))
                .andExpect(jsonPath("$.roles").isEmpty());
    }

    @Test
    void reportsAuthenticatedOidcSession() throws Exception {
        mockMvc.perform(get("/api/auth/session")
                        .with(oidcLogin()
                                .idToken(token -> token
                                        .claim("preferred_username", "student01"))
                                .authorities(new SimpleGrantedAuthority("ROLE_STUDENT"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticated").value(true))
                .andExpect(jsonPath("$.username").value("student01"))
                .andExpect(jsonPath("$.roles[0]").value("STUDENT"));
    }

    @Test
    void requiresAuthenticationBeforeIssuingCsrfToken() throws Exception {
        mockMvc.perform(get("/api/auth/csrf"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void issuesSessionBackedCsrfTokenForAuthenticatedUser() throws Exception {
        mockMvc.perform(get("/api/auth/csrf")
                        .with(oidcLogin()
                                .authorities(new SimpleGrantedAuthority("ROLE_STUDENT"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.headerName").value("X-CSRF-TOKEN"))
                .andExpect(jsonPath("$.parameterName").value("_csrf"));
    }
}
