package com.zerotrust.zerotrust.controller;

import com.zerotrust.zerotrust.config.SecurityConfig;
import com.zerotrust.zerotrust.exception.CustomAccessDeniedHandler;
import com.zerotrust.zerotrust.exception.CustomAuthenticationEntryPoint;
import com.zerotrust.zerotrust.security.KeycloakJwtAuthenticationConverter;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.ScoreResponseDTO;
import com.zerotrust.zerotrust.model.response.StudentResponseDTO;
import com.zerotrust.zerotrust.model.response.StudentClassResponseDTO;
import com.zerotrust.zerotrust.model.response.SubjectResponseDTO;
import com.zerotrust.zerotrust.service.ScoreAdministrationService;
import com.zerotrust.zerotrust.service.StudentAdministrationService;
import com.zerotrust.zerotrust.service.StudentClassAdministrationService;
import com.zerotrust.zerotrust.service.SubjectAdministrationService;
import com.zerotrust.zerotrust.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigDecimal;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AdminController.class)
@Import({SecurityConfig.class, CustomAuthenticationEntryPoint.class,
        CustomAccessDeniedHandler.class, KeycloakJwtAuthenticationConverter.class})
class AdminControllerSecurityTest {
    @Autowired
    private MockMvc mockMvc;
    @MockitoBean
    private ScoreAdministrationService scoreAdministrationService;
    @MockitoBean
    private StudentAdministrationService studentAdministrationService;
    @MockitoBean
    private StudentClassAdministrationService studentClassAdministrationService;
    @MockitoBean
    private SubjectAdministrationService subjectAdministrationService;
    @MockitoBean
    private UserService userService;
    @MockitoBean
    private JwtDecoder jwtDecoder;

    @Test
    void allowsPreflightFromConfiguredSpaOrigin() throws Exception {
        mockMvc.perform(options("/api/admin/students")
                        .header(HttpHeaders.ORIGIN, "http://localhost:3000")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS,
                                "authorization,content-type"))
                .andExpect(status().isOk())
                .andExpect(header().string(
                        HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,
                        "http://localhost:3000"));
    }

    @Test
    void rejectsPreflightFromUnknownOrigin() throws Exception {
        mockMvc.perform(options("/api/admin/students")
                        .header(HttpHeaders.ORIGIN, "https://evil.example")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    @Test
    void rejectsUnauthenticatedStudentCreation() throws Exception {
        mockMvc.perform(post("/api/admin/students")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validRequestJson()))
                .andExpect(status().isUnauthorized());

        verify(studentAdministrationService, never()).createStudent(any());
    }

    @Test
    void rejectsStudentRoleFromAdminEndpoint() throws Exception {
        mockMvc.perform(post("/api/admin/students")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_STUDENT")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validRequestJson()))
                .andExpect(status().isForbidden());

        verify(studentAdministrationService, never()).createStudent(any());
    }

    @Test
    void allowsBearerAuthenticatedMutationWithoutCsrfToken() throws Exception {
        when(studentAdministrationService.createStudent(any()))
                .thenReturn(org.mockito.Mockito.mock(StudentResponseDTO.class));

        mockMvc.perform(post("/api/admin/students")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validRequestJson()))
                .andExpect(status().isCreated());

        verify(studentAdministrationService).createStudent(any());
    }

    @Test
    void allowsAdminToCreateStudentAccount() throws Exception {
        when(studentAdministrationService.createStudent(any()))
                .thenReturn(org.mockito.Mockito.mock(StudentResponseDTO.class));

        mockMvc.perform(post("/api/admin/students")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validRequestJson()))
                .andExpect(status().isCreated());

        verify(studentAdministrationService).createStudent(any());
    }

    @Test
    void allowsAdminToCreateStudentClass() throws Exception {
        when(studentClassAdministrationService.createStudentClass(any()))
                .thenReturn(new StudentClassResponseDTO(
                        UUID.randomUUID(),
                        "AT19B",
                        "An toan thong tin 19B",
                        "An toan thong tin",
                        "2022-2026"));

        mockMvc.perform(post("/api/admin/student-classes")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validStudentClassRequestJson()))
                .andExpect(status().isCreated());

        verify(studentClassAdministrationService).createStudentClass(any());
    }

    @Test
    void allowsAdminToGetFilteredStudentClasses() throws Exception {
        StudentClassResponseDTO studentClass = new StudentClassResponseDTO(
                UUID.randomUUID(),
                "AT19B",
                "An toan thong tin 19B",
                "An toan thong tin",
                "2022-2026");
        PageResponse<StudentClassResponseDTO> response = new PageResponse<>(
                List.of(studentClass),
                0,
                20,
                1,
                1,
                true,
                true);
        when(studentClassAdministrationService.getStudentClasses(
                "AT19", "An toan thong tin", "2022-2026", 0, 20, "classCode,asc"))
                .thenReturn(response);

        mockMvc.perform(get("/api/admin/student-classes")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .param("keyword", "AT19")
                        .param("department", "An toan thong tin")
                        .param("academicYear", "2022-2026"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.content[0].classCode").value("AT19B"))
                .andExpect(jsonPath("$.data.totalElements").value(1));

        verify(studentClassAdministrationService).getStudentClasses(
                "AT19", "An toan thong tin", "2022-2026", 0, 20, "classCode,asc");
    }

    @Test
    void rejectsStudentRoleFromSubjectCreation() throws Exception {
        mockMvc.perform(post("/api/admin/subjects")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_STUDENT")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validSubjectRequestJson()))
                .andExpect(status().isForbidden());

        verify(subjectAdministrationService, never()).createSubject(any());
    }

    @Test
    void allowsAdminToCreateSubject() throws Exception {
        UUID subjectId = UUID.randomUUID();
        when(subjectAdministrationService.createSubject(any()))
                .thenReturn(new SubjectResponseDTO(
                        subjectId,
                        "SEC101",
                        "Nhap mon an toan thong tin",
                        (short) 3,
                        "Kien thuc co ban"));

        mockMvc.perform(post("/api/admin/subjects")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validSubjectRequestJson()))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.id").value(subjectId.toString()))
                .andExpect(jsonPath("$.data.subjectCode").value("SEC101"))
                .andExpect(jsonPath("$.data.credits").value(3));

        verify(subjectAdministrationService).createSubject(any());
    }

    @Test
    void rejectsStudentRoleFromSubjectList() throws Exception {
        mockMvc.perform(get("/api/admin/subjects")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_STUDENT"))))
                .andExpect(status().isForbidden());

        verify(subjectAdministrationService, never())
                .getSubjects(any(), anyInt(), anyInt(), any());
    }

    @Test
    void allowsAdminToGetFilteredSubjects() throws Exception {
        SubjectResponseDTO subject = new SubjectResponseDTO(
                UUID.randomUUID(),
                "SEC101",
                "Nhap mon an toan thong tin",
                (short) 3,
                "Kien thuc co ban");
        PageResponse<SubjectResponseDTO> response = new PageResponse<>(
                List.of(subject),
                0,
                20,
                1,
                1,
                true,
                true);
        when(subjectAdministrationService.getSubjects(
                "SEC", 0, 20, "subjectCode,asc"))
                .thenReturn(response);

        mockMvc.perform(get("/api/admin/subjects")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .param("keyword", "SEC"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.content[0].subjectCode").value("SEC101"))
                .andExpect(jsonPath("$.data.totalElements").value(1));

        verify(subjectAdministrationService).getSubjects(
                "SEC", 0, 20, "subjectCode,asc");
    }

    @Test
    void rejectsStudentRoleFromScoreCreation() throws Exception {
        UUID studentId = UUID.randomUUID();

        mockMvc.perform(post("/api/admin/students/{studentId}/scores", studentId)
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_STUDENT")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validScoreRequestJson(UUID.randomUUID())))
                .andExpect(status().isForbidden());

        verify(scoreAdministrationService, never()).createStudentScore(any(), any());
    }

    @Test
    void allowsAdminToCreateStudentScore() throws Exception {
        UUID studentId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        UUID scoreId = UUID.randomUUID();
        when(scoreAdministrationService.createStudentScore(any(), any()))
                .thenReturn(scoreResponse(scoreId, studentId, subjectId));

        mockMvc.perform(post("/api/admin/students/{studentId}/scores", studentId)
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validScoreRequestJson(subjectId)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.id").value(scoreId.toString()))
                .andExpect(jsonPath("$.data.studentId").value(studentId.toString()))
                .andExpect(jsonPath("$.data.subjectCode").value("SEC101"))
                .andExpect(jsonPath("$.data.totalScore").value(8.75));

        verify(scoreAdministrationService).createStudentScore(eq(studentId), any());
    }

    @Test
    void rejectsInvalidScorePayload() throws Exception {
        UUID studentId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();

        mockMvc.perform(post("/api/admin/students/{studentId}/scores", studentId)
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(invalidScoreRequestJson(subjectId)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_REQUEST"));

        verify(scoreAdministrationService, never()).createStudentScore(any(), any());
    }

    @Test
    void rejectsStudentRoleFromStudentScoreList() throws Exception {
        UUID studentId = UUID.randomUUID();

        mockMvc.perform(get("/api/admin/students/{studentId}/scores", studentId)
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_STUDENT"))))
                .andExpect(status().isForbidden());

        verify(scoreAdministrationService, never()).getStudentScores(
                any(), any(), any(), any(), anyInt(), anyInt(), any());
    }

    @Test
    void allowsAdminToGetFilteredStudentScores() throws Exception {
        UUID scoreId = UUID.randomUUID();
        UUID studentId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        PageResponse<ScoreResponseDTO> response = new PageResponse<>(
                List.of(scoreResponse(scoreId, studentId, subjectId)),
                0,
                10,
                1,
                1,
                true,
                true);
        when(scoreAdministrationService.getStudentScores(
                studentId,
                subjectId,
                (short) 1,
                "2025-2026",
                0,
                10,
                "totalScore,desc"))
                .thenReturn(response);

        mockMvc.perform(get("/api/admin/students/{studentId}/scores", studentId)
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .param("subjectId", subjectId.toString())
                        .param("semester", "1")
                        .param("academicYear", "2025-2026")
                        .param("size", "10")
                        .param("sort", "totalScore,desc"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.content[0].id").value(scoreId.toString()))
                .andExpect(jsonPath("$.data.content[0].subjectCode").value("SEC101"))
                .andExpect(jsonPath("$.data.content[0].totalScore").value(8.75))
                .andExpect(jsonPath("$.data.totalElements").value(1));

        verify(scoreAdministrationService).getStudentScores(
                studentId,
                subjectId,
                (short) 1,
                "2025-2026",
                0,
                10,
                "totalScore,desc");
    }

    @Test
    void rejectsStudentRoleFromScoreUpdate() throws Exception {
        UUID scoreId = UUID.randomUUID();

        mockMvc.perform(patch("/api/admin/scores/{scoreId}", scoreId)
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_STUDENT")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validScoreUpdateRequestJson()))
                .andExpect(status().isForbidden());

        verify(scoreAdministrationService, never()).updateScore(any(), any());
    }

    @Test
    void allowsAdminToUpdateScore() throws Exception {
        UUID scoreId = UUID.randomUUID();
        UUID studentId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        when(scoreAdministrationService.updateScore(any(), any()))
                .thenReturn(scoreResponse(scoreId, studentId, subjectId));

        mockMvc.perform(patch("/api/admin/scores/{scoreId}", scoreId)
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validScoreUpdateRequestJson()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.id").value(scoreId.toString()))
                .andExpect(jsonPath("$.data.totalScore").value(8.75));

        verify(scoreAdministrationService).updateScore(eq(scoreId), any());
    }

    @Test
    void rejectsInvalidScoreUpdatePayload() throws Exception {
        UUID scoreId = UUID.randomUUID();

        mockMvc.perform(patch("/api/admin/scores/{scoreId}", scoreId)
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "semester": 4,
                                  "finalScore": 11,
                                  "grade": "PASSED"
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_REQUEST"));

        verify(scoreAdministrationService, never()).updateScore(any(), any());
    }

    @Test
    void allowsAdminToGetFilteredStudents() throws Exception {
        StudentResponseDTO student = studentResponse(UUID.randomUUID());
        PageResponse<StudentResponseDTO> response = new PageResponse<>(
                List.of(student),
                0,
                20,
                1,
                1,
                true,
                true);
        when(studentAdministrationService.getStudents(
                "student01", "AT19B", "ACTIVE", 0, 20, "studentCode,asc"))
                .thenReturn(response);

        mockMvc.perform(get("/api/admin/students")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .param("keyword", "student01")
                        .param("classCode", "AT19B")
                        .param("status", "ACTIVE"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.content[0].studentCode").value("SV001"))
                .andExpect(jsonPath("$.data.totalElements").value(1));

        verify(studentAdministrationService).getStudents(
                "student01", "AT19B", "ACTIVE", 0, 20, "studentCode,asc");
    }

    @Test
    void allowsAdminToGetStudentDetails() throws Exception {
        UUID id = UUID.randomUUID();
        when(studentAdministrationService.getStudent(id)).thenReturn(studentResponse(id));

        mockMvc.perform(get("/api/admin/students/{id}", id)
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.id").value(id.toString()))
                .andExpect(jsonPath("$.data.studentCode").value("SV001"));

        verify(studentAdministrationService).getStudent(id);
    }

    @Test
    void rejectsStudentRoleFromStudentUpdateEndpoint() throws Exception {
        UUID id = UUID.randomUUID();

        mockMvc.perform(patch("/api/admin/students/{id}", id)
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_STUDENT")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validUpdateRequestJson()))
                .andExpect(status().isForbidden());

        verify(studentAdministrationService, never()).updateStudent(any(), any());
    }

    @Test
    void allowsAdminToUpdateStudentProfile() throws Exception {
        UUID id = UUID.randomUUID();
        when(studentAdministrationService.updateStudent(any(), any()))
                .thenReturn(studentResponse(id));

        mockMvc.perform(patch("/api/admin/students/{id}", id)
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validUpdateRequestJson()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.id").value(id.toString()));

        verify(studentAdministrationService).updateStudent(eq(id), any());
    }

    private String validRequestJson() {
        return """
                {
                  "username": "student01",
                  "password": "Temp@123456",
                  "email": "student01@example.com",
                  "firstName": "An",
                  "lastName": "Nguyen",
                  "studentCode": "SV001",
                  "dateOfBirth": "2003-05-20",
                  "gender": "MALE",
                  "phone": "0987654321",
                  "address": "Ha Noi",
                  "classCode": "AT19B"
                }
                """;
    }

    private String validStudentClassRequestJson() {
        return """
                {
                  "classCode": "AT19B",
                  "className": "An toan thong tin 19B",
                  "department": "An toan thong tin",
                  "academicYear": "2022-2026"
                }
                """;
    }

    private String validSubjectRequestJson() {
        return """
                {
                  "subjectCode": "SEC101",
                  "subjectName": "Nhap mon an toan thong tin",
                  "credits": 3,
                  "description": "Kien thuc co ban"
                }
                """;
    }

    private String validScoreRequestJson(UUID subjectId) {
        return """
                {
                  "subjectId": "%s",
                  "semester": 1,
                  "academicYear": "2025-2026",
                  "attendanceScore": 8.5,
                  "midtermScore": 8.0,
                  "finalScore": 9.0,
                  "totalScore": 8.75,
                  "grade": "B+"
                }
                """.formatted(subjectId);
    }

    private String invalidScoreRequestJson(UUID subjectId) {
        return """
                {
                  "subjectId": "%s",
                  "semester": 4,
                  "academicYear": "2025/2026",
                  "attendanceScore": 11,
                  "grade": "PASSED"
                }
                """.formatted(subjectId);
    }

    private String validScoreUpdateRequestJson() {
        return """
                {
                  "finalScore": 9.5,
                  "totalScore": 9.0,
                  "grade": "A"
                }
                """;
    }

    private ScoreResponseDTO scoreResponse(UUID scoreId, UUID studentId, UUID subjectId) {
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
                new BigDecimal("8.75"),
                "B+");
    }

    private String validUpdateRequestJson() {
        return """
                {
                  "email": "new.student@example.com",
                  "firstName": "Truong An",
                  "phone": "0987000000",
                  "classCode": "AT19C"
                }
                """;
    }

    private StudentResponseDTO studentResponse(UUID id) {
        return new StudentResponseDTO(
                id,
                UUID.randomUUID(),
                "student01",
                "student01@example.com",
                "An",
                "Nguyen",
                null,
                "SV001",
                java.time.LocalDate.of(2003, 5, 20),
                "MALE",
                "0987654321",
                "Ha Noi",
                "AT19B",
                "An toan thong tin 19B");
    }
}
