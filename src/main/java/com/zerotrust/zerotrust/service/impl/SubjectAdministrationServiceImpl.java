package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.entity.SubjectEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.request.CreateSubjectRequestDTO;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.SubjectResponseDTO;
import com.zerotrust.zerotrust.repository.ScoreRepository;
import com.zerotrust.zerotrust.repository.SubjectRepository;
import com.zerotrust.zerotrust.service.SubjectAdministrationService;
import com.zerotrust.zerotrust.service.support.QueryParameters;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.Locale;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class SubjectAdministrationServiceImpl implements SubjectAdministrationService {
    private static final String DEFAULT_SORT = "subjectCode,asc";
    private static final Set<String> ALLOWED_SORT_PROPERTIES = Set.of(
            "subjectCode",
            "subjectName",
            "credits");

    private final SubjectRepository subjectRepository;
    private final ScoreRepository scoreRepository;

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public SubjectResponseDTO createSubject(CreateSubjectRequestDTO request) {
        String subjectCode = request.getSubjectCode().trim().toUpperCase(Locale.ROOT);
        String subjectName = request.getSubjectName().trim();
        if (subjectRepository.existsBySubjectCodeIgnoreCase(subjectCode)) {
            throw new WebException(ErrorCode.SUBJECT_CODE_EXISTS);
        }
        if (subjectRepository.existsBySubjectNameIgnoreCase(subjectName)) {
            throw new WebException(ErrorCode.SUBJECT_NAME_EXISTS);
        }

        SubjectEntity subject = new SubjectEntity();
        subject.setSubjectCode(subjectCode);
        subject.setSubjectName(subjectName);
        subject.setCredits(request.getCredits());
        subject.setDescription(QueryParameters.normalizeOptional(request.getDescription()));

        try {
            // The repository rolls back a failed insert before we look up the conflicting fields.
            return toResponse(subjectRepository.saveAndFlush(subject));
        } catch (DataIntegrityViolationException ex) {
            throw translateCreationFailure(subjectCode, subjectName, ex);
        }
    }

    private RuntimeException translateCreationFailure(
            String subjectCode,
            String subjectName,
            DataIntegrityViolationException failure) {
        // A transactional caller owns rollback; do not query its failed persistence context.
        if (TransactionSynchronizationManager.isActualTransactionActive()) {
            return failure;
        }
        if (subjectRepository.existsBySubjectNameIgnoreCase(subjectName)) {
            return new WebException(ErrorCode.SUBJECT_NAME_EXISTS);
        }
        if (subjectRepository.existsBySubjectCodeIgnoreCase(subjectCode)) {
            return new WebException(ErrorCode.SUBJECT_CODE_EXISTS);
        }
        return failure;
    }

    @Override
    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteSubject(UUID subjectId) {
        SubjectEntity subject = subjectRepository.findById(subjectId)
                .orElseThrow(() -> new WebException(ErrorCode.SUBJECT_NOT_FOUND));
        if (scoreRepository.existsBySubjectEntityId(subjectId)) {
            throw new WebException(ErrorCode.SUBJECT_IN_USE);
        }

        try {
            subjectRepository.delete(subject);
            subjectRepository.flush();
        } catch (DataIntegrityViolationException ex) {
            throw new WebException(ErrorCode.SUBJECT_IN_USE);
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
        QueryParameters.validatePagination(page, size);
        Pageable pageable = PageRequest.of(
                page, size, QueryParameters.parseSort(sort, DEFAULT_SORT, ALLOWED_SORT_PROPERTIES));
        Page<SubjectResponseDTO> subjects = subjectRepository.findAllFiltered(
                        QueryParameters.normalizeOptional(keyword),
                        pageable)
                .map(this::toResponse);
        return PageResponse.from(subjects);
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
