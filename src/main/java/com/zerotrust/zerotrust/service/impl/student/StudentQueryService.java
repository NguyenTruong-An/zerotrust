package com.zerotrust.zerotrust.service.impl.student;

import com.zerotrust.zerotrust.converter.StudentConverter;
import com.zerotrust.zerotrust.entity.StudentEntity;
import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.StudentResponseDTO;
import com.zerotrust.zerotrust.repository.StudentRepository;
import com.zerotrust.zerotrust.service.support.QueryParameters;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class StudentQueryService {
    private static final String DEFAULT_SORT = "studentCode,asc";
    private static final Map<String, String> ALLOWED_SORT_PROPERTIES = Map.of(
            "studentCode", "studentCode",
            "username", "userEntity.username",
            "classCode", "studentClassEntity.classCode",
            "dateOfBirth", "dateOfBirth",
            "createdAt", "createdAt");

    private final StudentRepository studentRepository;
    private final StudentConverter studentConverter;

    @Transactional(readOnly = true)
    public PageResponse<StudentResponseDTO> getStudents(
            String keyword,
            String classCode,
            String status,
            int page,
            int size,
            String sort) {
        QueryParameters.validatePagination(page, size);
        Pageable pageable = PageRequest.of(
                page, size, QueryParameters.parseSort(sort, DEFAULT_SORT, ALLOWED_SORT_PROPERTIES));
        Page<StudentResponseDTO> students = studentRepository.findAllFiltered(
                        QueryParameters.normalizeOptional(keyword),
                        QueryParameters.normalizeOptional(classCode),
                        parseStatus(status),
                        pageable)
                .map(studentConverter::convertToDto);
        return PageResponse.from(students);
    }

    @Transactional(readOnly = true)
    public StudentResponseDTO getStudent(UUID id) {
        StudentEntity student = studentRepository.findDetailedById(id)
                .orElseThrow(() -> new WebException(ErrorCode.STUDENT_NOT_FOUND));
        return studentConverter.convertToDto(student);
    }

    @Transactional(readOnly = true)
    @PreAuthorize("hasRole('STUDENT')")
    public StudentResponseDTO getCurrentStudent(UUID keycloakUserId) {
        StudentEntity student = studentRepository.findByUserEntityKeycloakUserId(keycloakUserId)
                .orElseThrow(() -> new WebException(ErrorCode.STUDENT_NOT_FOUND));
        if (student.getUserEntity().getStatus() != UserEntity.Status.ACTIVE) {
            throw new WebException(ErrorCode.USER_INACTIVE);
        }
        return studentConverter.convertToDto(student);
    }

    private UserEntity.Status parseStatus(String status) {
        String normalizedStatus = QueryParameters.normalizeOptional(status);
        if (normalizedStatus == null) {
            return null;
        }

        try {
            return UserEntity.Status.valueOf(normalizedStatus.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            throw new WebException(
                    ErrorCode.INVALID_REQUEST,
                    "Status must be ACTIVE, INACTIVE or DELETED");
        }
    }

}
