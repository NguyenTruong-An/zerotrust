package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.entity.ScoreEntity;
import com.zerotrust.zerotrust.entity.StudentEntity;
import com.zerotrust.zerotrust.entity.SubjectEntity;
import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.request.CreateScoreRequestDTO;
import com.zerotrust.zerotrust.model.request.SubjectScoreItemRequestDTO;
import com.zerotrust.zerotrust.model.request.UpdateScoreRequestDTO;
import com.zerotrust.zerotrust.model.request.UpsertSubjectScoresRequestDTO;
import com.zerotrust.zerotrust.model.response.BatchScoreResponseDTO;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.ScoreResponseDTO;
import com.zerotrust.zerotrust.model.response.SubjectScoreSheetRowResponseDTO;
import com.zerotrust.zerotrust.model.response.StudentScoreSummaryResponseDTO;
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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Comparator;

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
                .existsByStudentEntityIdAndSubjectEntityId(studentId, request.getSubjectId())) {
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
        recalculateScore(score);

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
                        null,
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
            String keyword,
            Short semester,
            String academicYear,
            int page,
            int size,
            String sort) {
        validatePagination(page, size);
        validateSemester(semester);
        String normalizedKeyword = normalizeOptional(keyword);
        String normalizedAcademicYear = normalizeOptional(academicYear);
        if (normalizedAcademicYear != null) {
            validateAcademicYear(normalizedAcademicYear);
        }
        Pageable pageable = PageRequest.of(page, size, parseSort(sort));

        StudentEntity student = findActiveStudent(keycloakUserId);

        Page<ScoreResponseDTO> scores = scoreRepository.findAllByStudentFiltered(
                        student.getId(),
                        subjectId,
                        normalizedKeyword,
                        semester,
                        normalizedAcademicYear,
                        pageable)
                .map(this::toResponse);
        return PageResponse.from(scores);
    }

    @Override
    @Transactional(readOnly = true)
    @PreAuthorize("hasRole('STUDENT')")
    public StudentScoreSummaryResponseDTO getCurrentStudentScoreSummary(UUID keycloakUserId) {
        StudentEntity student = findActiveStudent(keycloakUserId);
        List<ScoreEntity> scores = scoreRepository.findAllByStudentEntityId(student.getId());
        List<BigDecimal> completedScores = scores.stream()
                .map(ScoreEntity::getTotalScore)
                .filter(java.util.Objects::nonNull)
                .toList();
        long passed = completedScores.stream()
                .filter(total -> total.compareTo(new BigDecimal("4.0")) >= 0)
                .count();
        BigDecimal average = completedScores.isEmpty()
                ? null
                : completedScores.stream()
                        .reduce(BigDecimal.ZERO, BigDecimal::add)
                        .divide(
                                BigDecimal.valueOf(completedScores.size()),
                                2,
                                RoundingMode.HALF_UP);
        BigDecimal highest = completedScores.stream()
                .max(BigDecimal::compareTo)
                .orElse(null);
        ScoreEntity latest = scores.stream()
                .max(Comparator
                        .comparing(ScoreEntity::getAcademicYear)
                        .thenComparing(ScoreEntity::getSemester))
                .orElse(null);

        return new StudentScoreSummaryResponseDTO(
                scores.size(),
                completedScores.size(),
                passed,
                completedScores.size() - passed,
                average,
                highest,
                latest == null ? null : latest.getSemester(),
                latest == null ? null : latest.getAcademicYear());
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

        boolean subjectChanged = !updatedSubject.getId().equals(currentSubject.getId());
        if (subjectChanged && scoreRepository
                .existsByStudentEntityIdAndSubjectEntityIdAndIdNot(
                        score.getStudentEntity().getId(),
                        updatedSubject.getId(),
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

    @Override
    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteScore(UUID scoreId) {
        ScoreEntity score = scoreRepository.findById(scoreId)
                .orElseThrow(() -> new WebException(ErrorCode.SCORE_NOT_FOUND));
        scoreRepository.delete(score);
    }

    @Override
    @Transactional(readOnly = true)
    @PreAuthorize("hasRole('ADMIN')")
    public PageResponse<SubjectScoreSheetRowResponseDTO> getSubjectScoreSheet(
            UUID subjectId,
            String classCode,
            String keyword,
            int page,
            int size) {
        validatePagination(page, size);
        String normalizedClassCode = normalizeOptional(classCode);
        if (normalizedClassCode == null) {
            throw new WebException(ErrorCode.INVALID_REQUEST, "Student class code is required");
        }
        subjectRepository.findById(subjectId)
                .orElseThrow(() -> new WebException(ErrorCode.SUBJECT_NOT_FOUND));

        Pageable pageable = PageRequest.of(
                page,
                size,
                Sort.by(Sort.Direction.ASC, "studentCode"));
        Page<StudentEntity> students = studentRepository.findAllFiltered(
                normalizeOptional(keyword),
                normalizedClassCode,
                UserEntity.Status.ACTIVE,
                pageable);
        List<UUID> studentIds = students.getContent().stream()
                .map(StudentEntity::getId)
                .toList();
        Map<UUID, ScoreEntity> scoreByStudentId = new HashMap<>();
        if (!studentIds.isEmpty()) {
            scoreRepository.findAllBySubjectEntityIdAndStudentEntityIdIn(subjectId, studentIds)
                    .forEach(score -> scoreByStudentId.put(
                            score.getStudentEntity().getId(), score));
        }

        return PageResponse.from(students.map(student ->
                toScoreSheetRow(student, scoreByStudentId.get(student.getId()))));
    }

    @Override
    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public BatchScoreResponseDTO upsertSubjectScores(
            UUID subjectId,
            UpsertSubjectScoresRequestDTO request) {
        if (request == null
                || request.getSemester() == null
                || request.getAcademicYear() == null
                || request.getAcademicYear().isBlank()) {
            throw new WebException(
                    ErrorCode.INVALID_REQUEST,
                    "Semester and academic year are required");
        }
        validateSemester(request.getSemester());
        validateAcademicYear(request.getAcademicYear());
        if (request.getScores() == null
                || request.getScores().isEmpty()
                || request.getScores().size() > MAX_PAGE_SIZE) {
            throw new WebException(
                    ErrorCode.INVALID_REQUEST,
                    "A batch must contain between 1 and 100 student scores");
        }

        SubjectEntity subject = subjectRepository.findById(subjectId)
                .orElseThrow(() -> new WebException(ErrorCode.SUBJECT_NOT_FOUND));
        Set<UUID> studentIds = new HashSet<>();
        for (SubjectScoreItemRequestDTO item : request.getScores()) {
            if (item == null || item.getStudentId() == null) {
                throw new WebException(ErrorCode.INVALID_REQUEST, "Student ID is required");
            }
            if (!studentIds.add(item.getStudentId())) {
                throw new WebException(
                        ErrorCode.INVALID_REQUEST,
                        "A student must appear only once in a score batch");
            }
        }

        Map<UUID, StudentEntity> studentById = new HashMap<>();
        studentRepository.findAllByIdIn(studentIds)
                .forEach(student -> studentById.put(student.getId(), student));
        if (studentById.size() != studentIds.size()) {
            throw new WebException(ErrorCode.STUDENT_NOT_FOUND);
        }
        if (studentById.values().stream()
                .anyMatch(student -> student.getUserEntity().getStatus() != UserEntity.Status.ACTIVE)) {
            throw new WebException(ErrorCode.USER_INACTIVE);
        }

        Map<UUID, ScoreEntity> existingByStudentId = new HashMap<>();
        scoreRepository.findAllBySubjectEntityIdAndStudentEntityIdIn(subjectId, studentIds)
                .forEach(score -> existingByStudentId.put(
                        score.getStudentEntity().getId(), score));

        int created = 0;
        String academicYear = request.getAcademicYear().trim();
        List<ScoreEntity> scoresToSave = new ArrayList<>(request.getScores().size());
        for (SubjectScoreItemRequestDTO item : request.getScores()) {
            ScoreEntity score = existingByStudentId.get(item.getStudentId());
            if (score == null) {
                score = new ScoreEntity();
                score.setStudentEntity(studentById.get(item.getStudentId()));
                score.setSubjectEntity(subject);
                created++;
            }
            score.setSemester(request.getSemester());
            score.setAcademicYear(academicYear);
            score.setAttendanceScore(item.getAttendanceScore());
            score.setMidtermScore(item.getMidtermScore());
            score.setFinalScore(item.getFinalScore());
            recalculateScore(score);
            scoresToSave.add(score);
        }

        try {
            scoreRepository.saveAllAndFlush(scoresToSave);
        } catch (DataIntegrityViolationException ex) {
            throw new WebException(ErrorCode.SCORE_EXISTS);
        }

        return new BatchScoreResponseDTO(
                created,
                scoresToSave.size() - created,
                scoresToSave.stream().map(this::toResponse).toList());
    }

    private void validateScoreUpdateRequest(UpdateScoreRequestDTO request) {
        if (request.getSubjectId() == null
                && request.getSemester() == null
                && request.getAcademicYear() == null
                && request.getAttendanceScore() == null
                && request.getMidtermScore() == null
                && request.getFinalScore() == null) {
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
        recalculateScore(score);
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
        if (endYear != startYear + 1) {
            throw new WebException(
                    ErrorCode.INVALID_REQUEST,
                    "Academic year must cover exactly one year");
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
        if (semester != null && (semester < 1 || semester > 2)) {
            throw new WebException(
                    ErrorCode.INVALID_REQUEST,
                    "Semester must be between 1 and 2");
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

    private void recalculateScore(ScoreEntity score) {
        if (score.getAttendanceScore() == null
                || score.getMidtermScore() == null
                || score.getFinalScore() == null) {
            score.setTotalScore(null);
            score.setGrade(null);
            return;
        }

        ScoreCalculator.Result result = ScoreCalculator.calculate(
                score.getAttendanceScore(),
                score.getMidtermScore(),
                score.getFinalScore());
        score.setTotalScore(result.totalScore());
        score.setGrade(result.grade());
    }

    private StudentEntity findActiveStudent(UUID keycloakUserId) {
        StudentEntity student = studentRepository.findByUserEntityKeycloakUserId(keycloakUserId)
                .orElseThrow(() -> new WebException(ErrorCode.STUDENT_NOT_FOUND));
        if (student.getUserEntity().getStatus() != UserEntity.Status.ACTIVE) {
            throw new WebException(ErrorCode.USER_INACTIVE);
        }
        return student;
    }

    private SubjectScoreSheetRowResponseDTO toScoreSheetRow(
            StudentEntity student,
            ScoreEntity score) {
        return new SubjectScoreSheetRowResponseDTO(
                score == null ? null : score.getId(),
                student.getId(),
                student.getStudentCode(),
                student.getUserEntity().getFirstName(),
                student.getUserEntity().getLastName(),
                student.getStudentClassEntity().getClassCode(),
                student.getStudentClassEntity().getClassName(),
                score == null ? null : score.getSemester(),
                score == null ? null : score.getAcademicYear(),
                score == null ? null : score.getAttendanceScore(),
                score == null ? null : score.getMidtermScore(),
                score == null ? null : score.getFinalScore(),
                score == null ? null : score.getTotalScore(),
                score == null ? null : score.getGrade());
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
