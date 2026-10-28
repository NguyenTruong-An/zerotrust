package com.zerotrust.zerotrust;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
class ZerotrustApplicationTests {
    @Autowired
    private MockMvc mockMvc;

    @Test
    void contextLoads() {
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/teachers/me", "/api/teachers/me/assignments", "/api/teachers/me/schedule",
            "/api/admin/teachers", "/api/admin/teaching-assignments", "/api/admin/schedules",
            "/api/students/me/schedule"
    })
    void removedTeachingAndScheduleEndpointsAreNotExposed(String path) throws Exception {
        mockMvc.perform(get(path).with(jwt().authorities(
                        new SimpleGrantedAuthority("ROLE_ADMIN"),
                        new SimpleGrantedAuthority("ROLE_STUDENT"))))
                .andExpect(status().isNotFound());
    }
}
