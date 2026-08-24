package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.entity.SubjectEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.request.CreateSubjectRequestDTO;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.SubjectResponseDTO;
import com.zerotrust.zerotrust.repository.SubjectRepository;
import com.zerotrust.zerotrust.service.SubjectAdministrationService;
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
import java.util.Set;

@Service
@RequiredArgsConstructor
public class SubjectAdministrationServiceImpl implements SubjectAdministrationService {
    private static final int MAX_PAGE_SIZE = 100;
    private static final String DEFAULT_SORT = "subjectCode,asc";
    private static final Set<String> ALLOWED_SORT_PROPERTIES = Set.of(
            "subjectCode",
            "subjectName",
            "credits");

    private final SubjectRepository subjectRepository;

    @Override
    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public SubjectResponseDTO createSubject(CreateSubjectRequestDTO request) {
        String subjectCode = request.getSubjectCode().trim().toUpperCase(Locale.ROOT);
        if (subjectRepository.existsBySubjectCodeIgnoreCase(subjectCode)) {
            throw new WebException(ErrorCode.SUBJECT_CODE_EXISTS);
        }

        SubjectEntity subject = new SubjectEntity();
        subject.setSubjectCode(subjectCode);
        subject.setSubjectName(request.getSubjectName().trim());
        subject.setCredits(request.getCredits());
        subject.setDescription(normalizeOptional(request.getDescription()));

        try {
            return toResponse(subjectRepository.saveAndFlush(subject));
        } catch (DataIntegrityViolationException ex) {
            throw new WebException(ErrorCode.SUBJECT_CODE_EXISTS);
        }
    }

    @Override
    @Transactional(readOnly = true)
    @PreAuthorize("hasRole('ADMIN')")
    public PageResponse<SubjectResponseDTO> getSubjects(
            String keyword,
            int page,
            int size,
            String sort) {
        validatePagination(page, size);
        Pageable pageable = PageRequest.of(page, size, parseSort(sort));
        Page<SubjectResponseDTO> subjects = subjectRepository.findAllFiltered(
                        normalizeOptional(keyword),
                        pageable)
                .map(this::toResponse);
        return PageResponse.from(subjects);
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

    private Sort parseSort(String sort) {
        String normalizedSort = normalizeOptional(sort);
        String[] parts = (normalizedSort == null ? DEFAULT_SORT : normalizedSort).split(",", -1);
        if (parts.length > 2) {
            throw invalidSort();
        }

        String property = parts[0].trim();
        if (!ALLOWED_SORT_PROPERTIES.contains(property)) {
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

    private SubjectResponseDTO toResponse(SubjectEntity subject) {
        return new SubjectResponseDTO(
                subject.getId(),
                subject.getSubjectCode(),
                subject.getSubjectName(),
                subject.getCredits(),
                subject.getDescription());
    }
}
