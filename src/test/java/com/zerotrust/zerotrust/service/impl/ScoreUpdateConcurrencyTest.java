package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.entity.ScoreEntity;
import com.zerotrust.zerotrust.entity.StudentClassEntity;
import com.zerotrust.zerotrust.entity.StudentEntity;
import com.zerotrust.zerotrust.entity.SubjectEntity;
import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.model.request.UpdateScoreRequestDTO;
import com.zerotrust.zerotrust.model.response.ScoreResponseDTO;
import com.zerotrust.zerotrust.repository.ScoreRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DataJpaTest(showSql = false)
@ActiveProfiles("test")
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(ScoreAdministrationServiceImpl.class)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class ScoreUpdateConcurrencyTest {
    private static final int TIMEOUT_SECONDS = 10;

    @Autowired
    private ScoreAdministrationServiceImpl service;
    @Autowired
    private ScoreRepository scoreRepository;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @PersistenceContext
    private EntityManager entityManager;

    private Fixture fixture;

    @BeforeEach
    void setUp() {
        fixture = transaction().execute(status -> persistFixture());
    }

    @AfterEach
    void cleanUp() {
        if (fixture == null) {
            return;
        }
        transaction().executeWithoutResult(status -> {
            remove(ScoreEntity.class, fixture.scoreId());
            remove(StudentEntity.class, fixture.studentId());
            remove(SubjectEntity.class, fixture.subjectId());
            remove(UserEntity.class, fixture.userId());
            remove(StudentClassEntity.class, fixture.classId());
        });
    }

    @Test
    void rejectsStaleTransactionAndPreservesCommittedScoresAndCalculatedResult() throws Exception {
        CountDownLatch bothRead = new CountDownLatch(2);
        CountDownLatch firstCommitted = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);

        try {
            Future<ScoreResponseDTO> first = executor.submit(() -> {
                try {
                    return transaction().execute(status -> {
                        readOriginalScore(bothRead);
                        return service.updateScore(fixture.scoreId(), UpdateScoreRequestDTO.builder()
                                .midtermScore(new BigDecimal("8.00"))
                                .build());
                    });
                } finally {
                    firstCommitted.countDown();
                }
            });
            Future<ScoreResponseDTO> second = executor.submit(() -> transaction().execute(status -> {
                readOriginalScore(bothRead);
                await(firstCommitted);
                // The service joins this transaction and reads its already loaded, stale entity.
                return service.updateScore(fixture.scoreId(), UpdateScoreRequestDTO.builder()
                        .finalScore(new BigDecimal("10.00"))
                        .build());
            }));

            ScoreResponseDTO committed = first.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            assertThat(committed.midtermScore()).isEqualByComparingTo("8.00");
            assertThat(committed.finalScore()).isEqualByComparingTo("9.00");
            assertThat(committed.totalScore()).isEqualByComparingTo("8.7");
            assertThat(committed.grade()).isEqualTo("A");
            assertThatThrownBy(() -> second.get(TIMEOUT_SECONDS, TimeUnit.SECONDS))
                    .isInstanceOf(ExecutionException.class)
                    .hasCauseInstanceOf(OptimisticLockingFailureException.class);

            transaction().executeWithoutResult(status -> {
                ScoreEntity stored = scoreRepository.findById(fixture.scoreId()).orElseThrow();
                assertThat(stored.getVersion()).isEqualTo(1L);
                assertThat(stored.getAttendanceScore()).isEqualByComparingTo("8.00");
                assertThat(stored.getMidtermScore()).isEqualByComparingTo("8.00");
                assertThat(stored.getFinalScore()).isEqualByComparingTo("9.00");
                assertThat(stored.getTotalScore()).isEqualByComparingTo("8.7");
                assertThat(stored.getGrade()).isEqualTo("A");
                assertThat(stored.getSubjectEntity().getId()).isEqualTo(fixture.subjectId());
                assertThat(stored.getStudentEntity().getId()).isEqualTo(fixture.studentId());
            });
        } finally {
            executor.shutdownNow();
            assertThat(executor.awaitTermination(TIMEOUT_SECONDS, TimeUnit.SECONDS)).isTrue();
        }
    }

    private void readOriginalScore(CountDownLatch bothRead) {
        ScoreEntity original = scoreRepository.findById(fixture.scoreId()).orElseThrow();
        assertThat(original.getVersion()).isZero();
        assertThat(original.getMidtermScore()).isEqualByComparingTo("7.00");
        assertThat(original.getFinalScore()).isEqualByComparingTo("9.00");
        bothRead.countDown();
        await(bothRead);
    }

    private void await(CountDownLatch latch) {
        try {
            if (!latch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Concurrent score test did not reach its checkpoint");
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Concurrent score test was interrupted", ex);
        }
    }

    private TransactionTemplate transaction() {
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);
        transaction.setTimeout(TIMEOUT_SECONDS);
        return transaction;
    }

    private Fixture persistFixture() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        StudentClassEntity studentClass = new StudentClassEntity();
        studentClass.setClassCode("CLASS_" + suffix);
        studentClass.setClassName("Concurrency test class");
        studentClass.setDepartment("Test department");
        studentClass.setCourseYears("2022-2027");
        entityManager.persist(studentClass);

        UserEntity user = new UserEntity();
        user.setKeycloakUserId(UUID.randomUUID());
        user.setUsername("score_test_" + suffix);
        user.setEmail(suffix + "@example.invalid");
        user.setFirstName("Test");
        user.setLastName("Student");
        entityManager.persist(user);

        StudentEntity student = new StudentEntity();
        student.setUserEntity(user);
        student.setStudentClassEntity(studentClass);
        student.setStudentCode("STUDENT_" + suffix);
        student.setDateOfBirth(LocalDate.of(2003, 1, 1));
        student.setGender("OTHER");
        entityManager.persist(student);

        SubjectEntity subject = new SubjectEntity();
        subject.setSubjectCode("SUBJECT_" + suffix);
        subject.setSubjectName("Concurrency test " + suffix);
        subject.setCredits((short) 3);
        entityManager.persist(subject);

        ScoreEntity score = new ScoreEntity();
        score.setStudentEntity(student);
        score.setSubjectEntity(subject);
        score.setSemester((short) 1);
        score.setAcademicYear("2025-2026");
        score.setAttendanceScore(new BigDecimal("8.00"));
        score.setMidtermScore(new BigDecimal("7.00"));
        score.setFinalScore(new BigDecimal("9.00"));
        score.setTotalScore(new BigDecimal("8.5"));
        score.setGrade("A");
        entityManager.persist(score);
        return new Fixture(score.getId(), student.getId(), subject.getId(), user.getId(), studentClass.getId());
    }

    private <T> void remove(Class<T> type, UUID id) {
        T entity = entityManager.find(type, id);
        if (entity != null) {
            entityManager.remove(entity);
        }
    }

    private record Fixture(UUID scoreId, UUID studentId, UUID subjectId, UUID userId, UUID classId) {
    }
}
