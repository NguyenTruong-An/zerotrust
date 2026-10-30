package com.zerotrust.zerotrust.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.zerotrust.entity.*;
import com.zerotrust.zerotrust.identity.IdentityProviderGateway;
import com.zerotrust.zerotrust.risk.RiskDeviceAdminClient;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Real controller/security/service/JPA chain. H2-only, rolled back; no canonical data or IdP calls. */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:portal-acceptance;MODE=MySQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE",
        "spring.datasource.driver-class-name=org.h2.Driver", "spring.datasource.username=sa",
        "spring.datasource.password=", "spring.jpa.hibernate.ddl-auto=create-drop"})
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class SchoolPortalPersistenceAcceptanceTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired EntityManager entities;
    @MockitoBean IdentityProviderGateway identity;
    @MockitoBean RiskDeviceAdminClient risk;
    private StudentEntity owner;
    private StudentEntity other;
    private SubjectEntity subject;

    @BeforeEach
    void fixturesAreEntirelyInMemory() {
        StudentClassEntity studentClass = new StudentClassEntity();
        studentClass.setClassCode("ACCEPTANCE_CLASS");
        studentClass.setClassName("Isolated acceptance class");
        studentClass.setDepartment("Test");
        studentClass.setCourseYears("2025-2029");
        entities.persist(studentClass);
        owner = student("OWNER", studentClass);
        other = student("OTHER", studentClass);
        subject = new SubjectEntity();
        subject.setSubjectCode("ACCEPTANCE_SUBJECT");
        subject.setSubjectName("Isolated acceptance subject");
        subject.setCredits((short) 3);
        entities.persist(subject);
        entities.flush();
    }

    @Test
    void scoreLifecycleAndValidationPersistThroughTheHttpContract() throws Exception {
        String endpoint = "/api/admin/students/" + owner.getId() + "/scores";
        String payload = """
                {"subjectId":"%s","semester":1,"academicYear":"2025-2026",
                 "attendanceScore":8,"midtermScore":7,"finalScore":9}
                """.formatted(subject.getId());
        String body = mvc.perform(post(endpoint).with(admin()).contentType(MediaType.APPLICATION_JSON).content(payload))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.data.totalScore").value(8.5))
                .andReturn().getResponse().getContentAsString();
        UUID scoreId = UUID.fromString(json.readTree(body).path("data").path("id").asText());
        mvc.perform(post(endpoint).with(admin()).contentType(MediaType.APPLICATION_JSON).content(payload))
                .andExpect(status().isBadRequest()); // Existing duplicate contract is 400, not 409.
        mvc.perform(patch("/api/admin/scores/" + scoreId).with(admin())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"finalScore\":11}"))
                .andExpect(status().isBadRequest());
        assertThat(entities.find(ScoreEntity.class, scoreId).getFinalScore()).isEqualByComparingTo("9");
        mvc.perform(patch("/api/admin/scores/" + scoreId).with(admin())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"midtermScore\":8}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.totalScore").value(8.7));

        mvc.perform(get("/api/students/me/scores").with(studentRole(owner))
                        .param("studentId", other.getId().toString()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.totalElements").value(1))
                .andExpect(jsonPath("$.data.content[0].studentId").value(owner.getId().toString()))
                .andExpect(jsonPath("$.data.content[0].totalScore").value(8.7));
        mvc.perform(get("/api/students/me/scores").with(studentRole(other))
                        .param("studentId", owner.getId().toString()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.totalElements").value(0));
        mvc.perform(delete("/api/admin/scores/" + scoreId).with(studentRole(owner)))
                .andExpect(status().isForbidden());
        assertThat(entities.find(ScoreEntity.class, scoreId)).isNotNull();
        mvc.perform(delete("/api/admin/scores/" + scoreId).with(admin())).andExpect(status().isNoContent());
        assertThat(entities.find(ScoreEntity.class, scoreId)).isNull();
        verifyNoInteractions(identity, risk);
    }

    @Test
    void classAndSubjectCreateDeleteAndInUseProtectionUseRealPersistence() throws Exception {
        String classBody = mvc.perform(post("/api/admin/student-classes").with(admin())
                        .contentType(MediaType.APPLICATION_JSON).content("""
                        {"classCode":"TEMP","className":"Temporary","department":"Test","courseYears":"2025-2029"}
                        """))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        String subjectBody = mvc.perform(post("/api/admin/subjects").with(admin())
                        .contentType(MediaType.APPLICATION_JSON).content("""
                        {"subjectCode":"TEMP","subjectName":"Temporary","credits":3}
                        """))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        mvc.perform(delete("/api/admin/student-classes/" + json.readTree(classBody).path("data").path("id").asText())
                .with(admin())).andExpect(status().isNoContent());
        mvc.perform(delete("/api/admin/subjects/" + json.readTree(subjectBody).path("data").path("id").asText())
                .with(admin())).andExpect(status().isNoContent());
        mvc.perform(delete("/api/admin/student-classes/" + owner.getStudentClassEntity().getId())
                .with(admin())).andExpect(status().isConflict());
        assertThat(entities.find(StudentEntity.class, owner.getId())).isNotNull();
        verifyNoInteractions(identity, risk);
    }

    private StudentEntity student(String suffix, StudentClassEntity studentClass) {
        UserEntity user = new UserEntity();
        user.setKeycloakUserId(UUID.randomUUID());
        user.setUsername("isolated_" + suffix);
        user.setEmail(suffix.toLowerCase() + "@example.invalid");
        user.setFirstName("Test"); user.setLastName(suffix);
        entities.persist(user);
        StudentEntity student = new StudentEntity();
        student.setUserEntity(user); student.setStudentClassEntity(studentClass);
        student.setStudentCode("ISOLATED_" + suffix);
        student.setDateOfBirth(LocalDate.of(2003, 1, 1)); student.setGender("OTHER");
        entities.persist(student);
        return student;
    }

    private RequestPostProcessor admin() {
        return jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    private RequestPostProcessor studentRole(StudentEntity student) {
        return jwt().jwt(j -> j.subject(student.getUserEntity().getKeycloakUserId().toString()))
                .authorities(new SimpleGrantedAuthority("ROLE_STUDENT"));
    }
}
