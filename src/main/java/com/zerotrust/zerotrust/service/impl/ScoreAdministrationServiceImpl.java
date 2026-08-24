package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.entity.ScoreEntity;
import com.zerotrust.zerotrust.entity.StudentEntity;
import com.zerotrust.zerotrust.entity.SubjectEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.request.CreateScoreRequestDTO;
import com.zerotrust.zerotrust.model.request.UpdateScoreRequestDTO;
import com.zerotrust.zerotrust.model.response.ScoreResponseDTO;
import com.zerotrust.zerotrust.repository.ScoreRepository;
import com.zerotrust.zerotrust.repository.StudentRepository;
import com.zerotrust.zerotrust.repository.SubjectRepository;
import com.zerotrust.zerotrust.service.ScoreAdministrationService;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ScoreAdministrationServiceImpl implements ScoreAdministrationService {
    private final ScoreRepository scoreRepository;
    private final StudentRepository studentRepository;
    private final SubjectRepository subjectRepository;

    @Override
    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public ScoreResponseDTO createStudentScore(
            UUID studentId,
            CreateScoreRequestDTO request) {
        validateAcademicYear(request.getAcademicYear());

        StudentEntity student = studentRepository.findById(studentId)
                .orElseThrow(() -> new WebException(ErrorCode.STUDENT_NOT_FOUND));
        SubjectEntity subject = subjectRepository.findById(request.getSubjectId())
                .orElseThrow(() -> new WebException(ErrorCode.SUBJECT_NOT_FOUND));
        String academicYear = request.getAcademicYear().trim();

        if (scoreRepository
                .existsByStudentEntityIdAndSubjectEntityIdAndSemesterAndAcademicYear(
                        studentId,
                        request.getSubjectId(),
                        request.getSemester(),
                        academicYear)) {
            throw new WebException(ErrorCode.SCORE_EXISTS);
        }

        ScoreEntity score = new ScoreEntity();
        score.setStudentEntity(student);
        score.setSubjectEntity(subject);
        score.setSemester(request.getSemester());
        score.setAcademicYear(academicYear);
        score.setAttendanceScore(request.getAttendanceScore());
        score.setMidtermScore(request.getMidtermScore());
        score.setFinalScore(request.getFinalScore());
        score.setTotalScore(request.getTotalScore());
        score.setGrade(normalizeGrade(request.getGrade()));

        try {
            return toResponse(scoreRepository.saveAndFlush(score));
        } catch (DataIntegrityViolationException ex) {
            throw new WebException(ErrorCode.SCORE_EXISTS);
        }
    }

    @Override
    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public ScoreResponseDTO updateScore(UUID scoreId, UpdateScoreRequestDTO request) {
        validateScoreUpdateRequest(request);

        ScoreEntity score = scoreRepository.findById(scoreId)
                .orElseThrow(() -> new WebException(ErrorCode.SCORE_NOT_FOUND));
        SubjectEntity currentSubject = score.getSubjectEntity();
        SubjectEntity updatedSubject = currentSubject;
        if (request.getSubjectId() != null
                && !request.getSubjectId().equals(currentSubject.getId())) {
            updatedSubject = subjectRepository.findById(request.getSubjectId())
                    .orElseThrow(() -> new WebException(ErrorCode.SUBJECT_NOT_FOUND));
        }

        Short updatedSemester = request.getSemester() == null
                ? score.getSemester()
                : request.getSemester();
        String updatedAcademicYear = score.getAcademicYear();
        if (request.getAcademicYear() != null) {
            validateAcademicYear(request.getAcademicYear());
            updatedAcademicYear = request.getAcademicYear().trim();
        }

        boolean termChanged = !updatedSubject.getId().equals(currentSubject.getId())
                || !updatedSemester.equals(score.getSemester())
                || !updatedAcademicYear.equals(score.getAcademicYear());
        if (termChanged && scoreRepository
                .existsByStudentEntityIdAndSubjectEntityIdAndSemesterAndAcademicYearAndIdNot(
                        score.getStudentEntity().getId(),
                        updatedSubject.getId(),
                        updatedSemester,
                        updatedAcademicYear,
                        scoreId)) {
            throw new WebException(ErrorCode.SCORE_EXISTS);
        }

        score.setSubjectEntity(updatedSubject);
        score.setSemester(updatedSemester);
        score.setAcademicYear(updatedAcademicYear);
        applyUpdatedScores(score, request);

        try {
            return toResponse(scoreRepository.saveAndFlush(score));
        } catch (DataIntegrityViolationException ex) {
            throw new WebException(ErrorCode.SCORE_EXISTS);
        }
    }

    private void validateScoreUpdateRequest(UpdateScoreRequestDTO request) {
        if (request.getSubjectId() == null
                && request.getSemester() == null
                && request.getAcademicYear() == null
                && request.getAttendanceScore() == null
                && request.getMidtermScore() == null
                && request.getFinalScore() == null
                && request.getTotalScore() == null
                && request.getGrade() == null) {
            throw new WebException(
                    ErrorCode.INVALID_REQUEST,
                    "At least one score field must be provided");
        }
    }

    private void applyUpdatedScores(ScoreEntity score, UpdateScoreRequestDTO request) {
        if (request.getAttendanceScore() != null) {
            score.setAttendanceScore(request.getAttendanceScore());
        }
        if (request.getMidtermScore() != null) {
            score.setMidtermScore(request.getMidtermScore());
        }
        if (request.getFinalScore() != null) {
            score.setFinalScore(request.getFinalScore());
        }
        if (request.getTotalScore() != null) {
            score.setTotalScore(request.getTotalScore());
        }
        if (request.getGrade() != null) {
            score.setGrade(normalizeGrade(request.getGrade()));
        }
    }

    private void validateAcademicYear(String academicYear) {
        String normalizedAcademicYear = academicYear.trim();
        if (!normalizedAcademicYear.matches("\\d{4}-\\d{4}")) {
            throw new WebException(
                    ErrorCode.INVALID_REQUEST,
                    "Academic year must use the format YYYY-YYYY");
        }

        int startYear = Integer.parseInt(normalizedAcademicYear.substring(0, 4));
        int endYear = Integer.parseInt(normalizedAcademicYear.substring(5));
        if (endYear <= startYear) {
            throw new WebException(
                    ErrorCode.INVALID_REQUEST,
                    "Academic year end must be later than its start");
        }
    }

    private String normalizeGrade(String grade) {
        if (grade == null || grade.isBlank()) {
            return null;
        }
        return grade.trim().toUpperCase(Locale.ROOT);
    }

    private ScoreResponseDTO toResponse(ScoreEntity score) {
        StudentEntity student = score.getStudentEntity();
        SubjectEntity subject = score.getSubjectEntity();
        return new ScoreResponseDTO(
                score.getId(),
                student.getId(),
                student.getStudentCode(),
                subject.getId(),
                subject.getSubjectCode(),
                subject.getSubjectName(),
                score.getSemester(),
                score.getAcademicYear(),
                score.getAttendanceScore(),
                score.getMidtermScore(),
                score.getFinalScore(),
                score.getTotalScore(),
                score.getGrade());
    }
}
