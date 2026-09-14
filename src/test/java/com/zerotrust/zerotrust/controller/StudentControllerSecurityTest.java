package com.zerotrust.zerotrust.controller;

import com.zerotrust.zerotrust.config.SecurityConfig;
import com.zerotrust.zerotrust.exception.CustomAccessDeniedHandler;
import com.zerotrust.zerotrust.exception.CustomAuthenticationEntryPoint;
import com.zerotrust.zerotrust.security.KeycloakJwtAuthenticationConverter;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.ScoreResponseDTO;
import com.zerotrust.zerotrust.model.response.StudentResponseDTO;
import com.zerotrust.zerotrust.model.response.StudentScoreSummaryResponseDTO;
import com.zerotrust.zerotrust.service.ScoreAdministrationService;
import com.zerotrust.zerotrust.service.impl.student.StudentQueryService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(StudentController.class)
@Import({SecurityConfig.class, CustomAuthenticationEntryPoint.class,
        CustomAccessDeniedHandler.class, KeycloakJwtAuthenticationConverter.class})
class StudentControllerSecurityTest {
    @Autowired
    private MockMvc mockMvc;
    @MockitoBean
    private ScoreAdministrationService scoreAdministrationService;
    @MockitoBean
    private StudentQueryService studentQueryService;
    @MockitoBean
    private JwtDecoder jwtDecoder;

    @Test
    void rejectsUnauthenticatedStudentScoreRequest() throws Exception {
        mockMvc.perform(get("/api/students/me/scores"))
                .andExpect(status().isUnauthorized());

        verify(scoreAdministrationService, never()).getCurrentStudentScores(
                any(), any(), any(), any(), any(), anyInt(), anyInt(), any());
    }

    @Test
    void returnsCurrentStudentProfileFromJwtSubject() throws Exception {
        UUID keycloakUserId = UUID.randomUUID();
        UUID studentId = UUID.randomUUID();
        StudentResponseDTO response = new StudentResponseDTO(
                studentId,
                UUID.randomUUID(),
                "student01",
                "student01@example.com",
                "An",
                "Nguyen",
                com.zerotrust.zerotrust.entity.UserEntity.Status.ACTIVE,
                "SV001",
                LocalDate.of(2003, 5, 20),
                "MALE",
                "0987654321",
                "Ha Noi",
                "AT19B",
                "An toan thong tin 19B");
        when(studentQueryService.getCurrentStudent(keycloakUserId)).thenReturn(response);

        mockMvc.perform(get("/api/students/me")
                        .with(jwt()
                                .jwt(token -> token.subject(keycloakUserId.toString()))
                                .authorities(new SimpleGrantedAuthority("ROLE_STUDENT"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.id").value(studentId.toString()))
                .andExpect(jsonPath("$.data.studentCode").value("SV001"))
                .andExpect(jsonPath("$.data.classCode").value("AT19B"));

        verify(studentQueryService).getCurrentStudent(keycloakUserId);
    }

    @Test
    void returnsCurrentStudentScoreSummary() throws Exception {
        UUID keycloakUserId = UUID.randomUUID();
        StudentScoreSummaryResponseDTO response = new StudentScoreSummaryResponseDTO(
                5,
                5,
                4,
                1,
                new BigDecimal("7.34"),
                new BigDecimal("9.2"),
                (short) 2,
                "2026-2027");
        when(scoreAdministrationService.getCurrentStudentScoreSummary(keycloakUserId))
                .thenReturn(response);

        mockMvc.perform(get("/api/students/me/scores/summary")
                        .with(jwt()
                                .jwt(token -> token.subject(keycloakUserId.toString()))
                                .authorities(new SimpleGrantedAuthority("ROLE_STUDENT"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.totalSubjects").value(5))
                .andExpect(jsonPath("$.data.failedSubjects").value(1))
                .andExpect(jsonPath("$.data.averageScore").value(7.34))
                .andExpect(jsonPath("$.data.latestAcademicYear").value("2026-2027"));

        verify(scoreAdministrationService).getCurrentStudentScoreSummary(keycloakUserId);
    }

    @Test
    void rejectsAdminWithoutStudentRole() throws Exception {
        mockMvc.perform(get("/api/students/me/scores")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isForbidden());

        verify(scoreAdministrationService, never()).getCurrentStudentScores(
                any(), any(), any(), any(), any(), anyInt(), anyInt(), any());
    }

    @Test
    void returnsOnlyScoresResolvedFromStudentJwtSubject() throws Exception {
        UUID keycloakUserId = UUID.randomUUID();
        UUID studentId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        UUID scoreId = UUID.randomUUID();
        PageResponse<ScoreResponseDTO> response = new PageResponse<>(
                List.of(score(scoreId, studentId, subjectId)),
                0,
                10,
                1,
                1,
                true,
                true);
        when(scoreAdministrationService.getCurrentStudentScores(
                keycloakUserId,
                subjectId,
                "security",
                (short) 1,
                "2025-2026",
                0,
                10,
                "totalScore,desc"))
                .thenReturn(response);

        mockMvc.perform(get("/api/students/me/scores")
                        .with(jwt()
                                .jwt(token -> token.subject(keycloakUserId.toString()))
                                .authorities(new SimpleGrantedAuthority("ROLE_STUDENT")))
                        .param("subjectId", subjectId.toString())
                        .param("keyword", "security")
                        .param("semester", "1")
                        .param("academicYear", "2025-2026")
                        .param("size", "10")
                        .param("sort", "totalScore,desc"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.content[0].id").value(scoreId.toString()))
                .andExpect(jsonPath("$.data.content[0].studentId").value(studentId.toString()))
                .andExpect(jsonPath("$.data.content[0].subjectCode").value("SEC101"))
                .andExpect(jsonPath("$.data.totalElements").value(1));

        verify(scoreAdministrationService).getCurrentStudentScores(
                keycloakUserId,
                subjectId,
                "security",
                (short) 1,
                "2025-2026",
                0,
                10,
                "totalScore,desc");
    }

    @Test
    void rejectsJwtWithNonUuidSubject() throws Exception {
        mockMvc.perform(get("/api/students/me/scores")
                        .with(jwt()
                                .jwt(token -> token.subject("not-a-keycloak-uuid"))
                                .authorities(new SimpleGrantedAuthority("ROLE_STUDENT"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("UNAUTHORIZED"));

        verify(scoreAdministrationService, never()).getCurrentStudentScores(
                any(), any(), any(), any(), any(), anyInt(), anyInt(), any());
    }

    private ScoreResponseDTO score(UUID scoreId, UUID studentId, UUID subjectId) {
        return new ScoreResponseDTO(
                scoreId,
                studentId,
                "SV001",
                subjectId,
                "SEC101",
                "Nhap mon an toan thong tin",
                (short) 1,
                "2025-2026",
                new BigDecimal("8.50"),
                new BigDecimal("8.00"),
                new BigDecimal("9.00"),
                new BigDecimal("8.7"),
                "A");
    }
}
