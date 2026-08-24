package com.zerotrust.zerotrust.service.impl.student;

import com.zerotrust.zerotrust.entity.StudentEntity;
import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.identity.IdentityProviderGateway;
import com.zerotrust.zerotrust.identity.model.IdentityUserProfileSnapshot;
import com.zerotrust.zerotrust.model.request.UpdateStudentRequestDTO;
import com.zerotrust.zerotrust.model.response.StudentResponseDTO;
import com.zerotrust.zerotrust.repository.StudentClassRepository;
import com.zerotrust.zerotrust.repository.StudentRepository;
import com.zerotrust.zerotrust.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

import java.util.Locale;
import java.util.Objects;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class StudentUpdateService {
    private final UserRepository userRepository;
    private final StudentRepository studentRepository;
    private final StudentClassRepository studentClassRepository;
    private final IdentityProviderGateway identityProviderGateway;
    private final StudentPersistenceService studentPersistenceService;

    public StudentResponseDTO updateStudent(UUID id, UpdateStudentRequestDTO request) {
        validateStudentUpdateRequest(request);

        StudentEntity student = studentRepository.findDetailedById(id)
                .orElseThrow(() -> new WebException(ErrorCode.STUDENT_NOT_FOUND));
        UserEntity user = student.getUserEntity();
        validateStudentUpdateData(id, user.getId(), request);

        String previousFirstName = user.getFirstName();
        String previousLastName = user.getLastName();
        String updatedEmail = request.getEmail() == null
                ? user.getEmail()
                : request.getEmail().trim().toLowerCase(Locale.ROOT);
        String updatedFirstName = request.getFirstName() == null
                ? previousFirstName
                : request.getFirstName().trim();
        String updatedLastName = request.getLastName() == null
                ? previousLastName
                : request.getLastName().trim();
        boolean identityUpdateRequired = !Objects.equals(previousFirstName, updatedFirstName)
                || !Objects.equals(previousLastName, updatedLastName)
                || !Objects.equals(user.getEmail(), updatedEmail);
        IdentityUserProfileSnapshot identityProfileSnapshot = null;

        if (identityUpdateRequired) {
            identityProfileSnapshot = identityProviderGateway.updateUserProfile(
                    user.getKeycloakUserId(),
                    updatedFirstName,
                    updatedLastName,
                    updatedEmail);
        }

        try {
            return studentPersistenceService.updateStudent(id, request);
        } catch (DataIntegrityViolationException ex) {
            rollbackIdentityProfile(
                    identityUpdateRequired,
                    user.getKeycloakUserId(),
                    identityProfileSnapshot);
            throw translateDataIntegrityViolation(id, user.getId(), request, ex);
        } catch (RuntimeException ex) {
            rollbackIdentityProfile(
                    identityUpdateRequired,
                    user.getKeycloakUserId(),
                    identityProfileSnapshot);
            throw ex;
        }
    }

    private void validateStudentUpdateRequest(UpdateStudentRequestDTO request) {
        if (request.getEmail() == null
                && request.getFirstName() == null
                && request.getLastName() == null
                && request.getStudentCode() == null
                && request.getDateOfBirth() == null
                && request.getGender() == null
                && request.getPhone() == null
                && request.getAddress() == null
                && request.getClassCode() == null) {
            throw new WebException(
                    ErrorCode.INVALID_REQUEST,
                    "At least one student profile field must be provided");
        }
    }

    private void validateStudentUpdateData(
            UUID studentId,
            UUID userId,
            UpdateStudentRequestDTO request) {
        if (request.getEmail() != null
                && userRepository.existsByEmailIgnoreCaseAndIdNot(
                request.getEmail().trim(), userId)) {
            throw new WebException(ErrorCode.EMAIL_EXISTS);
        }
        if (request.getStudentCode() != null
                && studentRepository.existsByStudentCodeIgnoreCaseAndIdNot(
                request.getStudentCode().trim(), studentId)) {
            throw new WebException(ErrorCode.STUDENT_CODE_EXISTS);
        }
        if (request.getClassCode() != null
                && !studentClassRepository.existsByClassCodeIgnoreCase(
                request.getClassCode().trim())) {
            throw new WebException(ErrorCode.STUDENT_CLASS_NOT_FOUND);
        }
    }

    private RuntimeException translateDataIntegrityViolation(
            UUID studentId,
            UUID userId,
            UpdateStudentRequestDTO request,
            DataIntegrityViolationException originalException) {
        if (request.getEmail() != null
                && userRepository.existsByEmailIgnoreCaseAndIdNot(
                request.getEmail().trim(), userId)) {
            return new WebException(ErrorCode.EMAIL_EXISTS);
        }
        if (request.getStudentCode() != null
                && studentRepository.existsByStudentCodeIgnoreCaseAndIdNot(
                request.getStudentCode().trim(), studentId)) {
            return new WebException(ErrorCode.STUDENT_CODE_EXISTS);
        }
        return originalException;
    }

    private void rollbackIdentityProfile(
            boolean identityUpdateRequired,
            UUID identityUserId,
            IdentityUserProfileSnapshot profileSnapshot) {
        if (identityUpdateRequired) {
            identityProviderGateway.restoreUserProfileQuietly(
                    identityUserId,
                    profileSnapshot);
        }
    }
}
