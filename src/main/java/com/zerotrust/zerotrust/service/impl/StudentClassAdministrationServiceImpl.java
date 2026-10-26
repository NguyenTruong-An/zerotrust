package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.entity.StudentClassEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.request.CreateStudentClassRequestDTO;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.StudentClassResponseDTO;
import com.zerotrust.zerotrust.repository.StudentClassRepository;
import com.zerotrust.zerotrust.repository.StudentRepository;
import com.zerotrust.zerotrust.service.StudentClassAdministrationService;
import com.zerotrust.zerotrust.service.support.QueryParameters;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class StudentClassAdministrationServiceImpl
        implements StudentClassAdministrationService {
    private static final String DEFAULT_SORT = "classCode,asc";
    private static final Set<String> ALLOWED_SORT_PROPERTIES = Set.of(
            "classCode",
            "className",
            "department",
            "courseYears");

    private final StudentClassRepository studentClassRepository;
    private final StudentRepository studentRepository;

    @Override
    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public StudentClassResponseDTO createStudentClass(CreateStudentClassRequestDTO request) {
        String classCode = request.getClassCode().trim().toUpperCase(Locale.ROOT);
        if (studentClassRepository.existsByClassCodeIgnoreCase(classCode)) {
            throw new WebException(ErrorCode.STUDENT_CLASS_CODE_EXISTS);
        }

        validateCourseYears(request.getCourseYears());

        StudentClassEntity studentClass = new StudentClassEntity();
        studentClass.setClassCode(classCode);
        studentClass.setClassName(request.getClassName().trim());
        studentClass.setDepartment(request.getDepartment().trim());
        studentClass.setCourseYears(request.getCourseYears().trim());

        try {
            StudentClassEntity savedClass = studentClassRepository.saveAndFlush(studentClass);
            return toResponse(savedClass);
        } catch (DataIntegrityViolationException ex) {
            throw new WebException(ErrorCode.STUDENT_CLASS_CODE_EXISTS);
        }
    }

    @Override
    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteStudentClass(UUID classId) {
        StudentClassEntity studentClass = studentClassRepository.findById(classId)
                .orElseThrow(() -> new WebException(ErrorCode.STUDENT_CLASS_NOT_FOUND));

        if (studentRepository.existsByStudentClassEntityId(classId)) {
            throw new WebException(ErrorCode.STUDENT_CLASS_IN_USE);
        }

        try {
            studentClassRepository.delete(studentClass);
            studentClassRepository.flush();
        } catch (DataIntegrityViolationException ex) {
            throw new WebException(ErrorCode.STUDENT_CLASS_IN_USE);
        }
    }

    @Override
    @Transactional(readOnly = true)
    @PreAuthorize("hasRole('ADMIN')")
    public PageResponse<StudentClassResponseDTO> getStudentClasses(
            String keyword,
            String department,
            String courseYears,
            int page,
            int size,
            String sort) {
        QueryParameters.validatePagination(page, size);
        String normalizedCourseYears = QueryParameters.normalizeOptional(courseYears);
        if (normalizedCourseYears != null) {
            validateCourseYears(normalizedCourseYears);
        }

        Pageable pageable = PageRequest.of(
                page, size, QueryParameters.parseSort(sort, DEFAULT_SORT, ALLOWED_SORT_PROPERTIES));
        Page<StudentClassResponseDTO> studentClasses = studentClassRepository.findAllFiltered(
                        QueryParameters.normalizeOptional(keyword),
                        QueryParameters.normalizeOptional(department),
                        normalizedCourseYears,
                        pageable)
                .map(this::toResponse);
        return PageResponse.from(studentClasses);
    }

    private void validateCourseYears(String courseYears) {
        String normalizedCourseYears = courseYears.trim();
        if (!normalizedCourseYears.matches("\\d{4}-\\d{4}")) {
            throw new WebException(
                    ErrorCode.INVALID_REQUEST,
                    "Course years must use the format YYYY-YYYY");
        }

        int startYear = Integer.parseInt(normalizedCourseYears.substring(0, 4));
        int endYear = Integer.parseInt(normalizedCourseYears.substring(5));
        if (endYear <= startYear) {
            throw new WebException(
                    ErrorCode.INVALID_REQUEST,
                    "Course end year must be later than its start year");
        }
    }

    private StudentClassResponseDTO toResponse(StudentClassEntity studentClass) {
        return new StudentClassResponseDTO(
                studentClass.getId(),
                studentClass.getClassCode(),
                studentClass.getClassName(),
                studentClass.getDepartment(),
                studentClass.getCourseYears());
    }
}
