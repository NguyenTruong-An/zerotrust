package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.entity.ScoreEntity;
import com.zerotrust.zerotrust.entity.StudentEntity;
import com.zerotrust.zerotrust.entity.SubjectEntity;
import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.request.CreateScoreRequestDTO;
import com.zerotrust.zerotrust.model.request.UpdateScoreRequestDTO;
import com.zerotrust.zerotrust.repository.ScoreRepository;
import com.zerotrust.zerotrust.repository.StudentRepository;
import com.zerotrust.zerotrust.repository.SubjectRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScoreAdministrationServiceImplTest {
    @Mock
    private ScoreRepository scoreRepository;
    @Mock
    private StudentRepository studentRepository;
    @Mock
    private SubjectRepository subjectRepository;

    private ScoreAdministrationServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new ScoreAdministrationServiceImpl(
                scoreRepository,
                studentRepository,
                subjectRepository);
    }

    @Test
    void createsScoreForStudentSubjectAndTerm() {
        UUID studentId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        UUID scoreId = UUID.randomUUID();
        StudentEntity student = student(studentId);
        SubjectEntity subject = subject(subjectId);
        CreateScoreRequestDTO request = request(subjectId, "2025-2026");
        request.setGrade(" b+ ");
        when(studentRepository.findById(studentId)).thenReturn(Optional.of(student));
        when(subjectRepository.findById(subjectId)).thenReturn(Optional.of(subject));
        when(scoreRepository.saveAndFlush(any(ScoreEntity.class)))
                .thenAnswer(invocation -> {
                    ScoreEntity score = invocation.getArgument(0);
                    score.setId(scoreId);
                    return score;
                });

        var response = service.createStudentScore(studentId, request);

        ArgumentCaptor<ScoreEntity> scoreCaptor = ArgumentCaptor.forClass(ScoreEntity.class);
        verify(scoreRepository)
                .existsByStudentEntityIdAndSubjectEntityIdAndSemesterAndAcademicYear(
                        studentId,
                        subjectId,
                        (short) 1,
                        "2025-2026");
        verify(scoreRepository).saveAndFlush(scoreCaptor.capture());
        assertThat(scoreCaptor.getValue().getStudentEntity()).isSameAs(student);
        assertThat(scoreCaptor.getValue().getSubjectEntity()).isSameAs(subject);
        assertThat(scoreCaptor.getValue().getGrade()).isEqualTo("B+");
        assertThat(response.id()).isEqualTo(scoreId);
        assertThat(response.studentCode()).isEqualTo("SV001");
        assertThat(response.subjectCode()).isEqualTo("SEC101");
        assertThat(response.totalScore()).isEqualByComparingTo("8.75");
    }

    @Test
    void reportsMissingStudent() {
        UUID studentId = UUID.randomUUID();
        CreateScoreRequestDTO request = request(UUID.randomUUID(), "2025-2026");
        when(studentRepository.findById(studentId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.createStudentScore(studentId, request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.STUDENT_NOT_FOUND);
        verify(subjectRepository, never()).findById(any());
        verify(scoreRepository, never()).saveAndFlush(any());
    }

    @Test
    void reportsMissingSubject() {
        UUID studentId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        CreateScoreRequestDTO request = request(subjectId, "2025-2026");
        when(studentRepository.findById(studentId)).thenReturn(Optional.of(student(studentId)));
        when(subjectRepository.findById(subjectId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.createStudentScore(studentId, request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.SUBJECT_NOT_FOUND);
        verify(scoreRepository, never()).saveAndFlush(any());
    }

    @Test
    void rejectsDuplicateScoreBeforeSaving() {
        UUID studentId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        CreateScoreRequestDTO request = request(subjectId, "2025-2026");
        when(studentRepository.findById(studentId)).thenReturn(Optional.of(student(studentId)));
        when(subjectRepository.findById(subjectId)).thenReturn(Optional.of(subject(subjectId)));
        when(scoreRepository
                .existsByStudentEntityIdAndSubjectEntityIdAndSemesterAndAcademicYear(
                        studentId, subjectId, (short) 1, "2025-2026"))
                .thenReturn(true);

        assertThatThrownBy(() -> service.createStudentScore(studentId, request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.SCORE_EXISTS);
        verify(scoreRepository, never()).saveAndFlush(any());
    }

    @Test
    void rejectsAcademicYearWhoseEndIsNotLater() {
        CreateScoreRequestDTO request = request(UUID.randomUUID(), "2026-2025");

        assertThatThrownBy(() -> service.createStudentScore(UUID.randomUUID(), request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REQUEST);
        verify(studentRepository, never()).findById(any());
    }

    @Test
    void translatesConcurrentDuplicateIntoScoreExistsError() {
        UUID studentId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        CreateScoreRequestDTO request = request(subjectId, "2025-2026");
        when(studentRepository.findById(studentId)).thenReturn(Optional.of(student(studentId)));
        when(subjectRepository.findById(subjectId)).thenReturn(Optional.of(subject(subjectId)));
        when(scoreRepository.saveAndFlush(any(ScoreEntity.class)))
                .thenThrow(new DataIntegrityViolationException("duplicate score"));

        assertThatThrownBy(() -> service.createStudentScore(studentId, request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.SCORE_EXISTS);
    }

    @Test
    void listsFilteredScoresForStudent() {
        UUID studentId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        ScoreEntity score = score(UUID.randomUUID(), studentId, subjectId);
        when(studentRepository.existsById(studentId)).thenReturn(true);
        when(scoreRepository.findAllByStudentFiltered(
                any(), any(), any(), any(), any(Pageable.class)))
                .thenAnswer(invocation -> new PageImpl<>(
                        List.of(score),
                        invocation.getArgument(4),
                        5));

        var response = service.getStudentScores(
                studentId,
                subjectId,
                (short) 1,
                " 2025-2026 ",
                1,
                2,
                "subjectCode,desc");

        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(scoreRepository).findAllByStudentFiltered(
                org.mockito.ArgumentMatchers.eq(studentId),
                org.mockito.ArgumentMatchers.eq(subjectId),
                org.mockito.ArgumentMatchers.eq((short) 1),
                org.mockito.ArgumentMatchers.eq("2025-2026"),
                pageableCaptor.capture());
        Pageable pageable = pageableCaptor.getValue();
        Sort.Order subjectCodeOrder = pageable.getSort()
                .getOrderFor("subjectEntity.subjectCode");
        assertThat(pageable.getPageNumber()).isEqualTo(1);
        assertThat(pageable.getPageSize()).isEqualTo(2);
        assertThat(subjectCodeOrder).isNotNull();
        assertThat(subjectCodeOrder.getDirection()).isEqualTo(Sort.Direction.DESC);
        assertThat(response.content()).hasSize(1);
        assertThat(response.content().get(0).id()).isEqualTo(score.getId());
        assertThat(response.content().get(0).subjectCode()).isEqualTo("SEC101");
        assertThat(response.page()).isEqualTo(1);
        assertThat(response.size()).isEqualTo(2);
        assertThat(response.totalElements()).isEqualTo(5);
        assertThat(response.totalPages()).isEqualTo(3);
    }

    @Test
    void reportsMissingStudentWhenListingScores() {
        UUID studentId = UUID.randomUUID();
        when(studentRepository.existsById(studentId)).thenReturn(false);

        assertThatThrownBy(() -> service.getStudentScores(
                studentId, null, null, null, 0, 20, null))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.STUDENT_NOT_FOUND);
        verify(scoreRepository, never()).findAllByStudentFiltered(
                any(), any(), any(), any(), any());
    }

    @Test
    void rejectsInvalidStudentScoreListParameters() {
        assertThatThrownBy(() -> service.getStudentScores(
                UUID.randomUUID(), null, (short) 4, null, 0, 20, null))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REQUEST);
        assertThatThrownBy(() -> service.getStudentScores(
                UUID.randomUUID(), null, null, "2026-2025", 0, 20, null))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REQUEST);
        assertThatThrownBy(() -> service.getStudentScores(
                UUID.randomUUID(), null, null, null, -1, 20, null))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REQUEST);
        assertThatThrownBy(() -> service.getStudentScores(
                UUID.randomUUID(), null, null, null, 0, 101, null))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REQUEST);
        assertThatThrownBy(() -> service.getStudentScores(
                UUID.randomUUID(), null, null, null, 0, 20, "id,asc"))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REQUEST);
        verify(studentRepository, never()).existsById(any());
    }

    @Test
    void listsScoresForStudentResolvedFromKeycloakUserId() {
        UUID keycloakUserId = UUID.randomUUID();
        UUID studentId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        ScoreEntity score = score(UUID.randomUUID(), studentId, subjectId);
        StudentEntity student = student(studentId);
        UserEntity user = new UserEntity();
        user.setKeycloakUserId(keycloakUserId);
        user.setStatus(UserEntity.Status.ACTIVE);
        student.setUserEntity(user);
        when(studentRepository.findByUserEntityKeycloakUserId(keycloakUserId))
                .thenReturn(Optional.of(student));
        when(scoreRepository.findAllByStudentFiltered(
                any(), any(), any(), any(), any(Pageable.class)))
                .thenAnswer(invocation -> new PageImpl<>(
                        List.of(score),
                        invocation.getArgument(4),
                        1));

        var response = service.getCurrentStudentScores(
                keycloakUserId,
                subjectId,
                (short) 1,
                " 2025-2026 ",
                0,
                20,
                null);

        verify(scoreRepository).findAllByStudentFiltered(
                org.mockito.ArgumentMatchers.eq(studentId),
                org.mockito.ArgumentMatchers.eq(subjectId),
                org.mockito.ArgumentMatchers.eq((short) 1),
                org.mockito.ArgumentMatchers.eq("2025-2026"),
                any(Pageable.class));
        assertThat(response.content()).hasSize(1);
        assertThat(response.content().get(0).studentId()).isEqualTo(studentId);
        assertThat(response.content().get(0).id()).isEqualTo(score.getId());
    }

    @Test
    void reportsMissingStudentLinkedToCurrentIdentity() {
        UUID keycloakUserId = UUID.randomUUID();
        when(studentRepository.findByUserEntityKeycloakUserId(keycloakUserId))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.getCurrentStudentScores(
                keycloakUserId, null, null, null, 0, 20, null))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.STUDENT_NOT_FOUND);
        verify(scoreRepository, never()).findAllByStudentFiltered(
                any(), any(), any(), any(), any());
    }

    @Test
    void rejectsInactiveStudentWhenListingOwnScores() {
        UUID keycloakUserId = UUID.randomUUID();
        StudentEntity student = student(UUID.randomUUID());
        UserEntity user = new UserEntity();
        user.setStatus(UserEntity.Status.INACTIVE);
        student.setUserEntity(user);
        when(studentRepository.findByUserEntityKeycloakUserId(keycloakUserId))
                .thenReturn(Optional.of(student));

        assertThatThrownBy(() -> service.getCurrentStudentScores(
                keycloakUserId, null, null, null, 0, 20, null))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.USER_INACTIVE);
        verify(scoreRepository, never()).findAllByStudentFiltered(
                any(), any(), any(), any(), any());
    }

    @Test
    void updatesOnlyProvidedScoreFields() {
        UUID scoreId = UUID.randomUUID();
        UUID studentId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        ScoreEntity score = score(scoreId, studentId, subjectId);
        UpdateScoreRequestDTO request = UpdateScoreRequestDTO.builder()
                .finalScore(new BigDecimal("9.50"))
                .grade(" a ")
                .build();
        when(scoreRepository.findById(scoreId)).thenReturn(Optional.of(score));
        when(scoreRepository.saveAndFlush(score)).thenReturn(score);

        var response = service.updateScore(scoreId, request);

        assertThat(score.getAttendanceScore()).isEqualByComparingTo("8.50");
        assertThat(score.getMidtermScore()).isEqualByComparingTo("8.00");
        assertThat(score.getFinalScore()).isEqualByComparingTo("9.50");
        assertThat(score.getGrade()).isEqualTo("A");
        assertThat(response.finalScore()).isEqualByComparingTo("9.50");
        verify(subjectRepository, never()).findById(any());
        verify(scoreRepository, never())
                .existsByStudentEntityIdAndSubjectEntityIdAndSemesterAndAcademicYearAndIdNot(
                        any(), any(), any(), any(), any());
    }

    @Test
    void reportsMissingScoreDuringUpdate() {
        UUID scoreId = UUID.randomUUID();
        UpdateScoreRequestDTO request = UpdateScoreRequestDTO.builder()
                .finalScore(new BigDecimal("9.50"))
                .build();
        when(scoreRepository.findById(scoreId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.updateScore(scoreId, request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.SCORE_NOT_FOUND);
        verify(scoreRepository, never()).saveAndFlush(any());
    }

    @Test
    void rejectsEmptyScoreUpdate() {
        assertThatThrownBy(() -> service.updateScore(
                UUID.randomUUID(), new UpdateScoreRequestDTO()))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REQUEST);
        verify(scoreRepository, never()).findById(any());
    }

    @Test
    void reportsMissingSubjectDuringUpdate() {
        UUID scoreId = UUID.randomUUID();
        UUID newSubjectId = UUID.randomUUID();
        ScoreEntity score = score(scoreId, UUID.randomUUID(), UUID.randomUUID());
        UpdateScoreRequestDTO request = UpdateScoreRequestDTO.builder()
                .subjectId(newSubjectId)
                .build();
        when(scoreRepository.findById(scoreId)).thenReturn(Optional.of(score));
        when(subjectRepository.findById(newSubjectId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.updateScore(scoreId, request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.SUBJECT_NOT_FOUND);
        verify(scoreRepository, never()).saveAndFlush(any());
    }

    @Test
    void rejectsUpdateThatDuplicatesAnotherScoreTerm() {
        UUID scoreId = UUID.randomUUID();
        UUID studentId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        ScoreEntity score = score(scoreId, studentId, subjectId);
        UpdateScoreRequestDTO request = UpdateScoreRequestDTO.builder()
                .semester((short) 2)
                .academicYear("2026-2027")
                .build();
        when(scoreRepository.findById(scoreId)).thenReturn(Optional.of(score));
        when(scoreRepository
                .existsByStudentEntityIdAndSubjectEntityIdAndSemesterAndAcademicYearAndIdNot(
                        studentId, subjectId, (short) 2, "2026-2027", scoreId))
                .thenReturn(true);

        assertThatThrownBy(() -> service.updateScore(scoreId, request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.SCORE_EXISTS);
        verify(scoreRepository, never()).saveAndFlush(any());
    }

    @Test
    void rejectsAcademicYearWhoseEndIsNotLaterDuringUpdate() {
        UUID scoreId = UUID.randomUUID();
        ScoreEntity score = score(scoreId, UUID.randomUUID(), UUID.randomUUID());
        UpdateScoreRequestDTO request = UpdateScoreRequestDTO.builder()
                .academicYear("2027-2026")
                .build();
        when(scoreRepository.findById(scoreId)).thenReturn(Optional.of(score));

        assertThatThrownBy(() -> service.updateScore(scoreId, request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REQUEST);
        verify(scoreRepository, never()).saveAndFlush(any());
    }

    private CreateScoreRequestDTO request(UUID subjectId, String academicYear) {
        return CreateScoreRequestDTO.builder()
                .subjectId(subjectId)
                .semester((short) 1)
                .academicYear(academicYear)
                .attendanceScore(new BigDecimal("8.50"))
                .midtermScore(new BigDecimal("8.00"))
                .finalScore(new BigDecimal("9.00"))
                .totalScore(new BigDecimal("8.75"))
                .grade("B+")
                .build();
    }

    private StudentEntity student(UUID id) {
        StudentEntity student = new StudentEntity();
        student.setId(id);
        student.setStudentCode("SV001");
        return student;
    }

    private SubjectEntity subject(UUID id) {
        SubjectEntity subject = new SubjectEntity();
        subject.setId(id);
        subject.setSubjectCode("SEC101");
        subject.setSubjectName("Nhap mon an toan thong tin");
        return subject;
    }

    private ScoreEntity score(UUID scoreId, UUID studentId, UUID subjectId) {
        ScoreEntity score = new ScoreEntity();
        score.setId(scoreId);
        score.setStudentEntity(student(studentId));
        score.setSubjectEntity(subject(subjectId));
        score.setSemester((short) 1);
        score.setAcademicYear("2025-2026");
        score.setAttendanceScore(new BigDecimal("8.50"));
        score.setMidtermScore(new BigDecimal("8.00"));
        score.setFinalScore(new BigDecimal("9.00"));
        score.setTotalScore(new BigDecimal("8.75"));
        score.setGrade("B+");
        return score;
    }
}
