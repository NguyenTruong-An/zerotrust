package com.zerotrust.zerotrust.entity;

import com.zerotrust.zerotrust.repository.ScoreRepository;
import com.zerotrust.zerotrust.repository.StudentRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.test.context.ActiveProfiles;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DataJpaTest(showSql = false)
@ActiveProfiles("test")
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class ScoreEntityMappingTest {
    @Autowired
    private ScoreRepository scoreRepository;
    @Autowired
    private StudentRepository studentRepository;
    @PersistenceContext
    private EntityManager entityManager;

    @Test
    void storesScoreDirectlyAgainstStudentSubjectAndTerm() {
        StudentEntity student = persistStudent();
        SubjectEntity subject = persistSubject();

        ScoreEntity score = score(student, subject);
        entityManager.persist(score);
        entityManager.flush();
        entityManager.clear();

        ScoreEntity stored = entityManager.find(ScoreEntity.class, score.getId());
        assertThat(stored.getStudentEntity().getId()).isEqualTo(student.getId());
        assertThat(stored.getSubjectEntity().getId()).isEqualTo(subject.getId());
        assertThat(stored.getSemester()).isEqualTo((short) 1);
        assertThat(stored.getAcademicYear()).isEqualTo("2025-2026");
        assertThat(scoreRepository
                .existsByStudentEntityIdAndSubjectEntityIdAndSemesterAndAcademicYear(
                        student.getId(), subject.getId(), (short) 1, "2025-2026"))
                .isTrue();
        assertThat(scoreRepository
                .existsByStudentEntityIdAndSubjectEntityIdAndSemesterAndAcademicYearAndIdNot(
                        student.getId(),
                        subject.getId(),
                        (short) 1,
                        "2025-2026",
                        UUID.randomUUID()))
                .isTrue();
        assertThat(scoreRepository
                .existsByStudentEntityIdAndSubjectEntityIdAndSemesterAndAcademicYearAndIdNot(
                        student.getId(),
                        subject.getId(),
                        (short) 1,
                        "2025-2026",
                        stored.getId()))
                .isFalse();
        var filteredScores = scoreRepository.findAllByStudentFiltered(
                student.getId(),
                subject.getId(),
                (short) 1,
                "2025-2026",
                PageRequest.of(
                        0,
                        10,
                        Sort.by(Sort.Direction.ASC, "subjectEntity.subjectCode")));
        assertThat(filteredScores.getContent())
                .extracting(ScoreEntity::getId)
                .containsExactly(stored.getId());
        assertThat(filteredScores.getContent().get(0).getSubjectEntity().getSubjectCode())
                .isEqualTo("SEC101");
        assertThat(studentRepository.findByUserEntityKeycloakUserId(
                student.getUserEntity().getKeycloakUserId()))
                .map(StudentEntity::getId)
                .contains(student.getId());
    }

    @Test
    void rejectsDuplicateScoreForSameStudentSubjectAndTerm() {
        StudentEntity student = persistStudent();
        SubjectEntity subject = persistSubject();
        entityManager.persist(score(student, subject));
        entityManager.flush();

        entityManager.persist(score(student, subject));

        assertThatThrownBy(entityManager::flush)
                .isInstanceOf(ConstraintViolationException.class);
    }

    private StudentEntity persistStudent() {
        StudentClassEntity studentClass = new StudentClassEntity();
        studentClass.setClassCode("AT19B");
        studentClass.setClassName("An toan thong tin 19B");
        studentClass.setDepartment("An toan thong tin");
        studentClass.setAcademicYear("2022-2026");
        entityManager.persist(studentClass);

        UserEntity user = new UserEntity();
        user.setKeycloakUserId(UUID.randomUUID());
        user.setUsername("student01");
        user.setEmail("student01@example.com");
        user.setFirstName("An");
        user.setLastName("Nguyen");
        entityManager.persist(user);

        StudentEntity student = new StudentEntity();
        student.setUserEntity(user);
        student.setStudentClassEntity(studentClass);
        student.setStudentCode("SV001");
        student.setDateOfBirth(LocalDate.of(2003, 5, 20));
        student.setGender("MALE");
        entityManager.persist(student);
        return student;
    }

    private SubjectEntity persistSubject() {
        SubjectEntity subject = new SubjectEntity();
        subject.setSubjectCode("SEC101");
        subject.setSubjectName("Nhap mon an toan thong tin");
        subject.setCredits((short) 3);
        entityManager.persist(subject);
        return subject;
    }

    private ScoreEntity score(StudentEntity student, SubjectEntity subject) {
        ScoreEntity score = new ScoreEntity();
        score.setStudentEntity(student);
        score.setSubjectEntity(subject);
        score.setSemester((short) 1);
        score.setAcademicYear("2025-2026");
        score.setAttendanceScore(new BigDecimal("8.50"));
        return score;
    }
}
