package com.zerotrust.zerotrust.academic;

import com.zerotrust.zerotrust.config.SecurityConfig;
import com.zerotrust.zerotrust.controller.StudentScheduleController;
import com.zerotrust.zerotrust.exception.*;
import com.zerotrust.zerotrust.security.KeycloakJwtAuthenticationConverter;
import com.zerotrust.zerotrust.service.impl.StudentScheduleService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import java.util.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(StudentScheduleController.class)
@Import({SecurityConfig.class,CustomAuthenticationEntryPoint.class,CustomAccessDeniedHandler.class,KeycloakJwtAuthenticationConverter.class})
class StudentScheduleControllerSecurityTest {
    @Autowired MockMvc mvc;@MockitoBean StudentScheduleService service;@MockitoBean JwtDecoder decoder;
    @Test void ownScheduleCannotBeSelectedByClientStudentId() throws Exception {
        UUID a=UUID.randomUUID(),b=UUID.randomUUID();when(service.current(a)).thenReturn(List.of());
        mvc.perform(get("/api/students/me/schedule?studentId="+b).with(jwt().jwt(j->j.subject(a.toString())).authorities(new SimpleGrantedAuthority("ROLE_STUDENT"))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data").isArray());verify(service).current(a);verify(service,never()).current(b);
    }
    @Test void anonymousAndWrongRoleAreDenied() throws Exception {
        mvc.perform(get("/api/students/me/schedule")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/students/me/schedule").with(jwt().authorities(new SimpleGrantedAuthority("ROLE_TEACHER")))).andExpect(status().isForbidden());verifyNoInteractions(service);
    }
    @Test void malformedUuidSubjectIsRejected() throws Exception {
        mvc.perform(get("/api/students/me/schedule").with(jwt().jwt(j->j.subject("opaque-invalid-for-school")).authorities(new SimpleGrantedAuthority("ROLE_STUDENT"))))
                .andExpect(status().isUnauthorized());verifyNoInteractions(service);
    }
}
