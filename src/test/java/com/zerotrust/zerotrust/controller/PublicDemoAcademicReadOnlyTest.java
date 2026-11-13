package com.zerotrust.zerotrust.controller;

import com.zerotrust.zerotrust.entity.*;
import com.zerotrust.zerotrust.identity.IdentityProviderGateway;
import com.zerotrust.zerotrust.risk.RiskDeviceAdminClient;
import com.zerotrust.zerotrust.security.PublicDemoEndpoint;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.math.BigDecimal;
import java.net.URI;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Direct Backend filter/controller/service/JPA chain; synthetic H2 only, no external services. */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:public-demo-readonly;MODE=MySQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE",
        "app.public-demo.mode=public-demo", "app.public-demo.academic-read-only=true",
        "spring.mvc.hiddenmethod.filter.enabled=true"})
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(PublicDemoAcademicReadOnlyTest.ProbeConfiguration.class)
@Transactional
class PublicDemoAcademicReadOnlyTest {
    @Autowired MockMvc mvc;
    @Autowired EntityManager entities;
    @Autowired JdbcTemplate jdbc;
    @Autowired @Qualifier("requestMappingHandlerMapping") RequestMappingHandlerMapping mappings;
    @Autowired UnclassifiedMutationProbe probe;
    @MockitoBean IdentityProviderGateway identity;
    @MockitoBean RiskDeviceAdminClient risk;
    @MockitoBean com.zerotrust.zerotrust.security.StrictSecurityAuthorityClient authority;
    @MockitoBean com.zerotrust.zerotrust.security.StrictResetOrchestrator strictReset;
    private StudentEntity owner;
    private StudentEntity other;
    private SubjectEntity subject;
    private StudentClassEntity studentClass;
    private ScoreEntity score;

    @BeforeEach
    void syntheticFixturesOnly() {
        probe.calls.set(0);
        studentClass = new StudentClassEntity();
        studentClass.setClassCode("PD_CLASS"); studentClass.setClassName("Synthetic class");
        studentClass.setDepartment("Test"); studentClass.setCourseYears("2025-2029");
        entities.persist(studentClass);
        owner = student("OWNER"); other = student("OTHER");
        subject = new SubjectEntity();
        subject.setSubjectCode("PD_SUBJECT"); subject.setSubjectName("Synthetic subject");
        subject.setCredits((short) 3); entities.persist(subject);
        score = new ScoreEntity();
        score.setStudentEntity(owner); score.setSubjectEntity(subject);
        score.setAcademicYear("2025-2026"); score.setSemester((short) 1);
        score.setFinalScore(new BigDecimal("8.00")); entities.persist(score);
        entities.flush(); entities.clear();
    }

    @ParameterizedTest
    @MethodSource("mutationsWithRoles")
    void everyAcademicMutationIs403AndLeavesAllSchoolTablesUnchanged(
            String method, String path, String body, String role) throws Exception {
        Map<String, List<Map<String, Object>>> before = schoolSnapshot();
        mvc.perform(request(HttpMethod.valueOf(method), resolve(path)).with(role(role))
                        .contentType(MediaType.APPLICATION_JSON).content(resolve(body)))
                .andExpect(status().isForbidden());
        assertThat(schoolSnapshot()).isEqualTo(before);
        verifyNoInteractions(identity, risk);
    }

    @ParameterizedTest
    @MethodSource("academicMutations")
    void missingBearerIs401BeforeTheWriteGuard(String method, String path, String body) throws Exception {
        var before = schoolSnapshot();
        mvc.perform(request(HttpMethod.valueOf(method), resolve(path))
                        .contentType(MediaType.APPLICATION_JSON).content(resolve(body)))
                .andExpect(status().isUnauthorized());
        assertThat(schoolSnapshot()).isEqualTo(before);
        verifyNoInteractions(identity, risk);
    }

    @ParameterizedTest
    @MethodSource("readsWithMethods")
    void everyReviewedReadIncludingHeadKeepsItsContract(String method, String path, String role) throws Exception {
        var before = schoolSnapshot();
        mvc.perform(request(HttpMethod.valueOf(method), resolve(path)).with(role(role))
                        .param("classCode", "PD_CLASS"))
                .andExpect(status().isOk());
        assertThat(schoolSnapshot()).isEqualTo(before);
        verifyNoInteractions(identity, risk);
    }

    @Test
    void ownershipUsesJwtSubjectAndIgnoresCallerSuppliedStudentId() throws Exception {
        mvc.perform(get("/api/students/me").with(role("STUDENT"))
                        .param("studentId", other.getId().toString()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.id").value(owner.getId().toString()));
        mvc.perform(get("/api/students/me/scores").with(role("STUDENT"))
                        .param("studentId", other.getId().toString()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.totalElements").value(1))
                .andExpect(jsonPath("$.data.content[0].studentId").value(owner.getId().toString()));
        mvc.perform(get("/api/students/me/scores").with(jwt()
                        .jwt(j -> j.subject(other.getUserEntity().getKeycloakUserId().toString()))
                        .authorities(new SimpleGrantedAuthority("ROLE_STUDENT")))
                        .param("studentId", owner.getId().toString()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.totalElements").value(0));
        mvc.perform(get("/api/students/" + other.getId()).with(role("STUDENT")))
                .andExpect(status().isForbidden());
    }

    @Test
    void readAllowlistNeverReplacesRoleOrBearerAuthorization() throws Exception {
        mvc.perform(get("/api/admin/students").with(role("STUDENT"))).andExpect(status().isForbidden());
        mvc.perform(get("/api/students/me").with(role("ADMIN"))).andExpect(status().isForbidden());
        mvc.perform(get("/api/admin/students")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/students/me")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/admin/students").with(jwt())).andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @ValueSource(strings = {"PUT", "PATCH", "DELETE", "POST"})
    void unsupportedMethodsOnReadRoutesAre403(String method) throws Exception {
        var before = schoolSnapshot();
        mvc.perform(request(HttpMethod.valueOf(method), "/api/admin/users").with(role("ADMIN")))
                .andExpect(status().isForbidden());
        assertThat(schoolSnapshot()).isEqualTo(before);
        verifyNoInteractions(identity, risk);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/api//admin/students", "/api/admin/students/", "/api/admin/./students",
            "/api/admin/subjects/../students", "/api/admin/students;x=1",
            "/api/admin/%73tudents", "/api/admin%2fstudents", "/api/admin/students%5cnew"})
    void pathVariantsCannotWrite(String path) throws Exception {
        var before = schoolSnapshot();
        int status = mvc.perform(post(URI.create(path)).with(role("ADMIN"))
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andReturn().getResponse().getStatus();
        assertThat(status).isIn(400, 403); // Strict firewall rejection or the read-only guard.
        assertThat(schoolSnapshot()).isEqualTo(before);
        verifyNoInteractions(identity, risk);
    }

    @Test
    void methodOverridesAndHeadersCannotWrite() throws Exception {
        var before = schoolSnapshot();
        mvc.perform(post("/api/admin/scores/" + score.getId()).with(role("ADMIN"))
                        .param("_method", "DELETE"))
                .andExpect(status().isForbidden());
        mvc.perform(post("/api/admin/subjects").with(role("ADMIN"))
                        .header("X-HTTP-Method-Override", "GET").param("_method", "GET"))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/admin/subjects").with(role("ADMIN"))
                        .header("X-HTTP-Method-Override", "DELETE"))
                .andExpect(status().isOk()); // This header is not a supported override.
        assertThat(schoolSnapshot()).isEqualTo(before);
        verifyNoInteractions(identity, risk);
    }

    @Test
    void unclassifiedGetSideEffectAndMutationAliasesAreDefaultDenied() throws Exception {
        var before = schoolSnapshot();
        for (String path : List.of("/api/admin/students/purge", "/api/admin/new-academic-alias")) {
            mvc.perform(get(path).with(role("ADMIN"))).andExpect(status().isForbidden());
            mvc.perform(post(path).with(role("ADMIN"))).andExpect(status().isForbidden());
        }
        assertThat(probe.calls).hasValue(0);
        assertThat(schoolSnapshot()).isEqualTo(before);
    }

    @Test
    void preflightDoesNotAuthorizeTheFollowingWrite() throws Exception {
        mvc.perform(options("/api/admin/students").header("Origin", "http://localhost:3000")
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(status().isOk());
        mvc.perform(post("/api/admin/students").with(role("ADMIN")))
                .andExpect(status().isForbidden());
        verifyNoInteractions(identity, risk);
    }

    @Test
    void existingAdminMfaResetStillUsesRevokeResetCompleteWithoutSchoolWrites() throws Exception {
        var before = schoolSnapshot();
        mvc.perform(post("/api/admin/users/" + owner.getUserEntity().getId() + "/mfa/reset").with(freshAdmin()))
                .andExpect(status().isNoContent());
        UUID subjectId = owner.getUserEntity().getKeycloakUserId();
        org.mockito.Mockito.verify(strictReset).reset(any(),eq(subjectId.toString()));
        verifyNoInteractions(risk,identity);
        assertThat(schoolSnapshot()).isEqualTo(before);
    }

    @Test
    void adminWithoutFactorProofIsRejectedBeforeAnySecurityMutation() throws Exception {
        var before = schoolSnapshot();
        mvc.perform(post("/api/admin/users/" + owner.getUserEntity().getId() + "/mfa/reset").with(role("ADMIN")))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.error").value("FRESH_ADMIN_MFA_REQUIRED"));
        verifyNoInteractions(identity, risk);
        assertThat(schoolSnapshot()).isEqualTo(before);
    }

    private RequestPostProcessor freshAdmin() {
        String sub = owner.getUserEntity().getKeycloakUserId().toString();
        return jwt().jwt(j -> j.subject(sub).claim("azp", "zerotrust-spa")
                .claim("zt_mfa_subject", sub).claim("zt_mfa_client", "zerotrust-spa")
                .claim("zt_mfa_method", "otp").claim("zt_mfa_at", java.time.Instant.now().getEpochSecond()))
                .authorities(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    @Test
    void securityStateClassificationDoesNotGrantMfaResetToStudentsOrAnonymous() throws Exception {
        String path = "/api/admin/users/" + owner.getUserEntity().getId() + "/mfa/reset";
        mvc.perform(post(path).with(role("STUDENT"))).andExpect(status().isForbidden());
        mvc.perform(post(path)).andExpect(status().isUnauthorized());
        verifyNoInteractions(identity, risk);
    }

    @Test
    void endpointInventoryRequiresExplicitReviewWhenProductionMappingsChange() {
        Set<String> actual = mappings.getHandlerMethods().entrySet().stream()
                .filter(e -> Set.of(AdminController.class, StudentController.class, UserController.class)
                        .contains(e.getValue().getBeanType()))
                .flatMap(e -> e.getKey().getPatternValues().stream().flatMap(path ->
                        e.getKey().getMethodsCondition().getMethods().stream().map(method -> {
                            var reviewed = e.getValue().getMethodAnnotation(PublicDemoEndpoint.class);
                            return method + " " + path + " " + (reviewed == null ? "WRITE" : reviewed.value());
                        })))
                .collect(Collectors.toSet());
        Set<String> expected = Stream.concat(
                academicMutations().map(a -> {
                    Object[] v = a.get();
                    return v[0] + " " + inventoryPath(v[1].toString()) + " WRITE";
                }), Stream.concat(
                        reads().map(a -> "GET " + inventoryPath(a.get()[0].toString()) + " READ"),
                        Stream.of("POST /api/admin/users/{id}/mfa/reset SECURITY_STATE","POST /api/admin/users/{id}/mfa/reset/challenge SECURITY_STATE")))
                .collect(Collectors.toSet());
        assertThat(actual).hasSize(23).isEqualTo(expected);
    }

    private static Stream<Arguments> academicMutations() {
        return Stream.of(
                Arguments.of("POST", "/api/admin/student-classes", "{\"classCode\":\"NEW\",\"className\":\"New\",\"department\":\"Test\",\"courseYears\":\"2025-2029\"}"),
                Arguments.of("DELETE", "/api/admin/student-classes/{classId}", ""),
                Arguments.of("POST", "/api/admin/subjects", "{\"subjectCode\":\"NEW\",\"subjectName\":\"New\",\"credits\":3}"),
                Arguments.of("DELETE", "/api/admin/subjects/{subjectId}", ""),
                Arguments.of("POST", "/api/admin/subjects/{subjectId}/scores/batch", "{\"semester\":1,\"academicYear\":\"2025-2026\",\"scores\":[{\"studentId\":\"{studentId}\",\"finalScore\":10}]}"),
                Arguments.of("POST", "/api/admin/students/{studentId}/scores", "{\"subjectId\":\"{subjectId}\",\"semester\":1,\"academicYear\":\"2025-2026\",\"finalScore\":10}"),
                Arguments.of("PATCH", "/api/admin/scores/{scoreId}", "{\"finalScore\":10}"),
                Arguments.of("DELETE", "/api/admin/scores/{scoreId}", ""),
                Arguments.of("POST", "/api/admin/students", "{\"username\":\"synthetic_new\",\"email\":\"new@example.invalid\",\"password\":\"Test-only-123!\",\"firstName\":\"Test\",\"lastName\":\"New\",\"studentCode\":\"NEW\",\"dateOfBirth\":\"2003-01-01\",\"gender\":\"OTHER\",\"classCode\":\"PD_CLASS\"}"),
                Arguments.of("PATCH", "/api/admin/students/{id}", "{\"firstName\":\"Changed\",\"email\":\"changed@example.invalid\"}"));
    }

    private static Stream<Arguments> mutationsWithRoles() {
        return academicMutations().flatMap(a -> Stream.of("ADMIN", "STUDENT")
                .map(role -> Arguments.of(a.get()[0], a.get()[1], a.get()[2], role)));
    }

    private static Stream<Arguments> reads() {
        return Stream.of(
                Arguments.of("/api/admin/student-classes", "ADMIN"),
                Arguments.of("/api/admin/subjects", "ADMIN"),
                Arguments.of("/api/admin/subjects/{subjectId}/score-sheet", "ADMIN"),
                Arguments.of("/api/admin/students/{studentId}/scores", "ADMIN"),
                Arguments.of("/api/admin/students", "ADMIN"),
                Arguments.of("/api/admin/students/{id}", "ADMIN"),
                Arguments.of("/api/admin/users", "ADMIN"),
                Arguments.of("/api/students/me", "STUDENT"),
                Arguments.of("/api/students/me/scores", "STUDENT"),
                Arguments.of("/api/students/me/scores/summary", "STUDENT"),
                Arguments.of("/api/users/me", "STUDENT"));
    }

    private static Stream<Arguments> readsWithMethods() {
        return reads().flatMap(a -> Stream.of("GET", "HEAD")
                .map(method -> Arguments.of(method, a.get()[0], a.get()[1])));
    }

    private String resolve(String text) {
        return text.replace("{studentId}", owner.getId().toString()).replace("{id}", owner.getId().toString())
                .replace("{subjectId}", subject.getId().toString()).replace("{classId}", studentClass.getId().toString())
                .replace("{scoreId}", score.getId().toString());
    }

    private static String inventoryPath(String path) { return path; }

    private StudentEntity student(String suffix) {
        UserEntity user = new UserEntity(); user.setKeycloakUserId(UUID.randomUUID());
        user.setUsername("pd_" + suffix); user.setEmail(suffix.toLowerCase() + "@example.invalid");
        user.setFirstName("Synthetic"); user.setLastName(suffix); entities.persist(user);
        StudentEntity student = new StudentEntity(); student.setUserEntity(user);
        student.setStudentClassEntity(studentClass); student.setStudentCode("PD_" + suffix);
        student.setDateOfBirth(LocalDate.of(2003, 1, 1)); student.setGender("OTHER");
        entities.persist(student); return student;
    }

    private RequestPostProcessor role(String role) {
        return jwt().jwt(j -> j.subject(owner.getUserEntity().getKeycloakUserId().toString()))
                .authorities(new SimpleGrantedAuthority("ROLE_" + role));
    }

    private Map<String, List<Map<String, Object>>> schoolSnapshot() {
        entities.flush(); entities.clear();
        Map<String, List<Map<String, Object>>> result = new TreeMap<>();
        for (String table : List.of("users", "students", "student_classes", "subjects", "scores")) {
            result.put(table, new ArrayList<>(jdbc.queryForList("SELECT * FROM " + table + " ORDER BY id")));
        }
        return result;
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class ProbeConfiguration {
        @Bean UnclassifiedMutationProbe unclassifiedMutationProbe() { return new UnclassifiedMutationProbe(); }
    }

    @RestController
    static class UnclassifiedMutationProbe {
        final AtomicInteger calls = new AtomicInteger();
        @GetMapping({"/api/admin/students/purge", "/api/admin/new-academic-alias"})
        String sideEffectingGet() { calls.incrementAndGet(); return "unsafe"; }
        @PostMapping({"/api/admin/students/purge", "/api/admin/new-academic-alias"})
        String writeAlias() { calls.incrementAndGet(); return "unsafe"; }
    }
}
