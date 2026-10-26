package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.entity.SubjectEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.request.CreateSubjectRequestDTO;
import com.zerotrust.zerotrust.repository.SubjectRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DataJpaTest(showSql = false)
@ActiveProfiles("test")
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(SubjectAdministrationServiceImpl.class)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class SubjectCreationTransactionTest {
    @Autowired
    private SubjectAdministrationServiceImpl service;
    @MockitoSpyBean
    private SubjectRepository subjectRepository;
    @PersistenceContext
    private EntityManager entityManager;
    @Autowired
    private PlatformTransactionManager transactionManager;

    @AfterEach
    void cleanUp() {
        subjectRepository.deleteAllInBatch();
    }

    @Test
    void classifiesDuplicateNameAfterFailedInsertHasRolledBack() {
        seedSubject("SEC101", "Network security");
        AtomicBoolean firstCheck = new AtomicBoolean(true);
        // Simulate a stale precheck; the insert and the subsequent lookup use real JPA.
        doAnswer(invocation -> firstCheck.getAndSet(false) ? false :
                entityManager.createQuery(
                        "select count(s) from SubjectEntity s where s.subjectName = :name", Long.class)
                        .setParameter("name", "Network security").getSingleResult() > 0)
                .when(subjectRepository).existsBySubjectNameIgnoreCase("Network security");

        assertThatThrownBy(() -> service.createSubject(request("SEC102", "Network security", 3)))
                .isInstanceOfSatisfying(WebException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.SUBJECT_NAME_EXISTS));

        assertThat(subjectRepository.count()).isEqualTo(1);
        assertThat(subjectRepository.existsBySubjectCodeIgnoreCase("SEC102")).isFalse();
        assertThat(service.createSubject(request("SEC103", "Cryptography", 3)).subjectCode())
                .isEqualTo("SEC103");
    }

    @Test
    void preservesDatabaseCheckFailureAndRollsBackInsert() {
        assertThatThrownBy(() -> service.createSubject(request("SEC201", "Invalid credits", 21)))
                .isInstanceOf(DataIntegrityViolationException.class);

        assertThat(subjectRepository.count()).isZero();
    }

    @Test
    void preservesFailureWithoutFurtherQueriesWhenCallerOwnsTransaction() {
        seedSubject("SEC101", "Network security");
        doReturn(false).when(subjectRepository).existsBySubjectNameIgnoreCase("Network security");

        TransactionTemplate transaction = new TransactionTemplate(transactionManager);
        assertThatThrownBy(() -> transaction.executeWithoutResult(status ->
                service.createSubject(request("SEC102", "Network security", 3))))
                .isInstanceOf(DataIntegrityViolationException.class);

        verify(subjectRepository, times(1)).existsBySubjectNameIgnoreCase("Network security");
        assertThat(subjectRepository.count()).isEqualTo(1);
    }

    @Test
    void successfulInsertParticipatesInCallerRollback() {
        RuntimeException callerFailure = new IllegalStateException("caller operation failed");
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);

        assertThatThrownBy(() -> transaction.executeWithoutResult(status -> {
            service.createSubject(request("SEC301", "Application security", 3));
            throw callerFailure;
        })).isSameAs(callerFailure);

        assertThat(subjectRepository.count()).isZero();
    }

    private void seedSubject(String code, String name) {
        SubjectEntity subject = new SubjectEntity();
        subject.setSubjectCode(code);
        subject.setSubjectName(name);
        subject.setCredits((short) 3);
        subjectRepository.saveAndFlush(subject);
    }

    private CreateSubjectRequestDTO request(String code, String name, int credits) {
        return CreateSubjectRequestDTO.builder()
                .subjectCode(code).subjectName(name).credits((short) credits).build();
    }
}
