package com.zerotrust.zerotrust.config;

import com.zerotrust.zerotrust.controller.UserController;
import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.exception.CustomAccessDeniedHandler;
import com.zerotrust.zerotrust.exception.CustomAuthenticationEntryPoint;
import com.zerotrust.zerotrust.model.response.UserResponseDTO;
import com.zerotrust.zerotrust.security.KeycloakJwtAuthenticationConverter;
import com.zerotrust.zerotrust.service.UserService;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Security headers must survive the authentication and Public Demo denial paths after upgrades. */
@WebMvcTest(controllers = UserController.class, properties = {
        "app.public-demo.mode=public-demo", "app.public-demo.academic-read-only=true"})
@Import({SecurityConfig.class, CustomAuthenticationEntryPoint.class,
        CustomAccessDeniedHandler.class, KeycloakJwtAuthenticationConverter.class})
class FrameworkResponseHeadersTest {
    @Autowired MockMvc mvc;
    @MockitoBean UserService users;
    @MockitoBean JwtDecoder decoder;

    @ParameterizedTest
    @CsvSource({"GET,false,401", "GET,true,200", "POST,true,403"})
    void writesSecurityAndNoCacheHeadersOnSuccessAndRejections(
            String method, boolean authenticated, int expectedStatus) throws Exception {
        UUID subject = UUID.fromString("00000000-0000-4000-8000-000000000001");
        when(users.getCurrentUser(subject)).thenReturn(new UserResponseDTO(
                subject.toString(), "synthetic@example.invalid", "synthetic", "Test", "Only", UserEntity.Status.ACTIVE));
        var operation = request(HttpMethod.valueOf(method), "/api/users/me");
        if (authenticated) {
            operation.with(jwt().jwt(j -> j.subject(subject.toString())));
        }
        mvc.perform(operation)
                .andExpect(status().is(expectedStatus))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Cache-Control", org.hamcrest.Matchers.containsString("no-store")));
    }
}
