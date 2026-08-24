package com.zerotrust.zerotrust.controller;

import com.zerotrust.zerotrust.config.SecurityConfig;
import com.zerotrust.zerotrust.exception.CustomAuthenticationEntryPoint;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.StudentResponseDTO;
import com.zerotrust.zerotrust.model.response.StudentClassResponseDTO;
import com.zerotrust.zerotrust.service.StudentAdministrationService;
import com.zerotrust.zerotrust.service.StudentClassAdministrationService;
import com.zerotrust.zerotrust.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AdminController.class)
@Import({SecurityConfig.class, CustomAuthenticationEntryPoint.class})
class AdminControllerSecurityTest {
    @Autowired
    private MockMvc mockMvc;
    @MockitoBean
    private StudentAdministrationService studentAdministrationService;
    @MockitoBean
    private StudentClassAdministrationService studentClassAdministrationService;
    @MockitoBean
    private UserService userService;
    @MockitoBean
    private JwtDecoder jwtDecoder;

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
