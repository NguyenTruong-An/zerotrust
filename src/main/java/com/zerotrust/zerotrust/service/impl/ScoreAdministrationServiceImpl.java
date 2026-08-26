package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.entity.ScoreEntity;
import com.zerotrust.zerotrust.entity.StudentEntity;
import com.zerotrust.zerotrust.entity.SubjectEntity;
import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.request.CreateScoreRequestDTO;
import com.zerotrust.zerotrust.model.request.UpdateScoreRequestDTO;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.ScoreResponseDTO;
import com.zerotrust.zerotrust.repository.ScoreRepository;
import com.zerotrust.zerotrust.repository.StudentRepository;
import com.zerotrust.zerotrust.repository.SubjectRepository;
import com.zerotrust.zerotrust.service.ScoreAdministrationService;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ScoreAdministrationServiceImpl implements ScoreAdministrationService {
    private static final int MAX_PAGE_SIZE = 100;
    private static final String DEFAULT_SORT = "academicYear,desc";
    private static final Map<String, String> ALLOWED_SORT_PROPERTIES = Map.ofEntries(
            Map.entry("subjectCode", "subjectEntity.subjectCode"),
            Map.entry("subjectName", "subjectEntity.subjectName"),
            Map.entry("semester", "semester"),
            Map.entry("academicYear", "academicYear"),
            Map.entry("attendanceScore", "attendanceScore"),
            Map.entry("midtermScore", "midtermScore"),
            Map.entry("finalScore", "finalScore"),
            Map.entry("totalScore", "totalScore"),
            Map.entry("grade", "grade"),
            Map.entry("createdAt", "createdAt"));

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
    @Transactional(readOnly = true)
    @PreAuthorize("hasRole('ADMIN')")
    public PageResponse<ScoreResponseDTO> getStudentScores(
            UUID studentId,
            UUID subjectId,
            Short semester,
            String academicYear,
            int page,
            int size,
            String sort) {
        validatePagination(page, size);
        validateSemester(semester);
        String normalizedAcademicYear = normalizeOptional(academicYear);
        if (normalizedAcademicYear != null) {
            validateAcademicYear(normalizedAcademicYear);
        }
        Pageable pageable = PageRequest.of(page, size, parseSort(sort));

        if (!studentRepository.existsById(studentId)) {
            throw new WebException(ErrorCode.STUDENT_NOT_FOUND);
        }

        Page<ScoreResponseDTO> scores = scoreRepository.findAllByStudentFiltered(
                        studentId,
                        subjectId,
                        semester,
                        normalizedAcademicYear,
                        pageable)
                .map(this::toResponse);
        return PageResponse.from(scores);
    }

    @Override
    @Transactional(readOnly = true)
    @PreAuthorize("hasRole('STUDENT')")
    public PageResponse<ScoreResponseDTO> getCurrentStudentScores(
            UUID keycloakUserId,
            UUID subjectId,
            Short semester,
            String academicYear,
            int page,
            int size,
            String sort) {
        validatePagination(page, size);
        validateSemester(semester);
        String normalizedAcademicYear = normalizeOptional(academicYear);
        if (normalizedAcademicYear != null) {
            validateAcademicYear(normalizedAcademicYear);
        }
        Pageable pageable = PageRequest.of(page, size, parseSort(sort));

        StudentEntity student = studentRepository.findByUserEntityKeycloakUserId(keycloakUserId)
                .orElseThrow(() -> new WebException(ErrorCode.STUDENT_NOT_FOUND));
        if (student.getUserEntity().getStatus() != UserEntity.Status.ACTIVE) {
            throw new WebException(ErrorCode.USER_INACTIVE);
        }

        Page<ScoreResponseDTO> scores = scoreRepository.findAllByStudentFiltered(
                        student.getId(),
                        subjectId,
                        semester,
                        normalizedAcademicYear,
                        pageable)
                .map(this::toResponse);
        return PageResponse.from(scores);
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

    private void validatePagination(int page, int size) {
        if (page < 0) {
            throw new WebException(ErrorCode.INVALID_REQUEST, "Page must be zero or greater");
        }
        if (size < 1 || size > MAX_PAGE_SIZE) {
            throw new WebException(
                    ErrorCode.INVALID_REQUEST,
                    "Size must be between 1 and " + MAX_PAGE_SIZE);
        }
    }

    private void validateSemester(Short semester) {
        if (semester != null && (semester < 1 || semester > 3)) {
            throw new WebException(
                    ErrorCode.INVALID_REQUEST,
                    "Semester must be between 1 and 3");
        }
    }

    private Sort parseSort(String sort) {
        String normalizedSort = normalizeOptional(sort);
        String[] parts = (normalizedSort == null ? DEFAULT_SORT : normalizedSort).split(",", -1);
        if (parts.length > 2) {
            throw invalidSort();
        }

        String property = ALLOWED_SORT_PROPERTIES.get(parts[0].trim());
        if (property == null) {
            throw invalidSort();
        }

        Sort.Direction direction = Sort.Direction.ASC;
        if (parts.length == 2) {
            try {
                direction = Sort.Direction.fromString(parts[1].trim());
            } catch (IllegalArgumentException ex) {
                throw invalidSort();
            }
        }
        return Sort.by(direction, property);
    }

    private WebException invalidSort() {
        return new WebException(
                ErrorCode.INVALID_REQUEST,
                "Sort must use an allowed field followed by asc or desc");
    }

    private String normalizeOptional(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
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
