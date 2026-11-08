package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.entity.*;
import com.zerotrust.zerotrust.model.request.UpdateScoreRequestDTO;
import com.zerotrust.zerotrust.repository.ScoreRepository;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.UUID;
import static org.assertj.core.api.Assertions.assertThat;

/** Characterization of baseline, not the desired regression assertion after a fix.
 * Install ONLY into the isolated Git snapshot's test source directory.
 * Uses synthetic H2 records; no network, Keycloak, Lab DB or credentials.
 */
@DataJpaTest(showSql = false)
@ActiveProfiles("test")
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(ScoreAdministrationServiceImpl.class)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class StaleScoreEditAuditTest {
    @Autowired ScoreAdministrationServiceImpl service;
    @Autowired ScoreRepository scores;
    @Autowired EntityManager em;
    @Autowired PlatformTransactionManager manager;

    @Test
    void laterHttpStyleTransactionSilentlyOverwritesEarlierEditFromAStaleForm() {
        TransactionTemplate tx = new TransactionTemplate(manager);
        UUID id = tx.execute(status -> fixture());
        try {
            // Two browser forms obtained these original values before either save.
            var firstForm = UpdateScoreRequestDTO.builder()
                    .attendanceScore(new BigDecimal("8.00"))
                    .midtermScore(new BigDecimal("8.00"))
                    .finalScore(new BigDecimal("9.00")).build();
            var staleForm = UpdateScoreRequestDTO.builder()
                    .attendanceScore(new BigDecimal("8.00"))
                    .midtermScore(new BigDecimal("7.00"))
                    .finalScore(new BigDecimal("10.00")).build();
            tx.executeWithoutResult(status -> service.updateScore(id, firstForm));
            tx.executeWithoutResult(status -> {
                assertThat(scores.findById(id).orElseThrow().getVersion()).isEqualTo(1);
                assertThat(scores.findById(id).orElseThrow().getMidtermScore()).isEqualByComparingTo("8.00");
            });
            // Independent transaction loads version 1: Hibernate cannot know the form saw version 0.
            tx.executeWithoutResult(status -> service.updateScore(id, staleForm));
            tx.executeWithoutResult(status -> {
                var stored = scores.findById(id).orElseThrow();
                assertThat(stored.getVersion()).isEqualTo(2);
                assertThat(stored.getMidtermScore()).isEqualByComparingTo("7.00");
                assertThat(stored.getFinalScore()).isEqualByComparingTo("10.00");
            });
        } finally {
            tx.executeWithoutResult(status -> {
                var score = scores.findById(id).orElseThrow();
                var student = score.getStudentEntity();
                var subject = score.getSubjectEntity();
                var user = student.getUserEntity();
                var group = student.getStudentClassEntity();
                em.remove(score); em.flush(); em.remove(student); em.flush();
                em.remove(subject); em.remove(user); em.flush(); em.remove(group);
            });
        }
    }

    UUID fixture() {
        var suffix = UUID.randomUUID().toString().substring(0, 8);
        var group = new StudentClassEntity();
        group.setClassCode("AUDIT_" + suffix); group.setClassName("Synthetic audit class");
        group.setDepartment("Audit"); group.setCourseYears("2022-2027"); em.persist(group);
        var user = new UserEntity(); user.setKeycloakUserId(UUID.randomUUID());
        user.setUsername("audit_" + suffix); user.setEmail(suffix + "@example.invalid");
        user.setFirstName("Synthetic"); user.setLastName("Audit"); em.persist(user);
        var student = new StudentEntity(); student.setUserEntity(user); student.setStudentClassEntity(group);
        student.setStudentCode("AUDIT_" + suffix); student.setDateOfBirth(LocalDate.of(2003,1,1));
        student.setGender("OTHER"); em.persist(student);
        var subject = new SubjectEntity(); subject.setSubjectCode("AUDIT_" + suffix);
        subject.setSubjectName("Synthetic " + suffix); subject.setCredits((short)3); em.persist(subject);
        var score = new ScoreEntity(); score.setStudentEntity(student); score.setSubjectEntity(subject);
        score.setSemester((short)1); score.setAcademicYear("2025-2026");
        score.setAttendanceScore(new BigDecimal("8.00")); score.setMidtermScore(new BigDecimal("7.00"));
        score.setFinalScore(new BigDecimal("9.00")); score.setTotalScore(new BigDecimal("8.5"));
        score.setGrade("A"); em.persist(score); em.flush(); return score.getId();
    }
}
