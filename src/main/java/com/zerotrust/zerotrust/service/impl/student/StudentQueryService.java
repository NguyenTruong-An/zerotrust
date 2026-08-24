package com.zerotrust.zerotrust.service.impl.student;

import com.zerotrust.zerotrust.converter.StudentConverter;
import com.zerotrust.zerotrust.entity.StudentEntity;
import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.StudentResponseDTO;
import com.zerotrust.zerotrust.repository.StudentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class StudentQueryService {
    private static final int MAX_PAGE_SIZE = 100;
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
        validatePagination(page, size);
        Pageable pageable = PageRequest.of(page, size, parseSort(sort));
        Page<StudentResponseDTO> students = studentRepository.findAllFiltered(
                        normalizeOptional(keyword),
                        normalizeOptional(classCode),
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

    private UserEntity.Status parseStatus(String status) {
        String normalizedStatus = normalizeOptional(status);
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
}
