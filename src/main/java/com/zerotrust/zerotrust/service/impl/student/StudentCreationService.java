package com.zerotrust.zerotrust.service.impl.student;

import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.identity.IdentityProviderGateway;
import com.zerotrust.zerotrust.identity.model.CreateIdentityUserCommand;
import com.zerotrust.zerotrust.identity.model.ProvisionedIdentityUser;
import com.zerotrust.zerotrust.model.request.CreateStudentRequestDTO;
import com.zerotrust.zerotrust.model.response.StudentResponseDTO;
import com.zerotrust.zerotrust.repository.StudentClassRepository;
import com.zerotrust.zerotrust.repository.StudentRepository;
import com.zerotrust.zerotrust.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

import java.util.Locale;

@Service
@RequiredArgsConstructor
public class StudentCreationService {
    private static final String STUDENT_ROLE = "STUDENT";

    private final UserRepository userRepository;
    private final StudentRepository studentRepository;
    private final StudentClassRepository studentClassRepository;
    private final IdentityProviderGateway identityProviderGateway;
    private final StudentPersistenceService studentPersistenceService;

    public StudentResponseDTO createStudent(CreateStudentRequestDTO request) {
        validateLocalData(request);

        CreateIdentityUserCommand command = new CreateIdentityUserCommand(
                request.getUsername().trim(),
                request.getPassword(),
                request.getEmail().trim().toLowerCase(Locale.ROOT),
                request.getFirstName().trim(),
                request.getLastName().trim());
        ProvisionedIdentityUser provisionedUser = identityProviderGateway.createUser(command);

        try {
            identityProviderGateway.assignRealmRole(provisionedUser.userId(), STUDENT_ROLE);
            return studentPersistenceService.saveStudent(provisionedUser.userId(), request);
        } catch (DataIntegrityViolationException ex) {
            identityProviderGateway.deleteUserQuietly(provisionedUser);
            throw translateDataIntegrityViolation(request, ex);
        } catch (RuntimeException ex) {
            identityProviderGateway.deleteUserQuietly(provisionedUser);
            throw ex;
        }
    }

    private void validateLocalData(CreateStudentRequestDTO request) {
        if (userRepository.existsByUsernameIgnoreCase(request.getUsername().trim())) {
            throw new WebException(ErrorCode.USERNAME_EXISTS);
        }
        if (userRepository.existsByEmailIgnoreCase(request.getEmail().trim())) {
            throw new WebException(ErrorCode.EMAIL_EXISTS);
        }
        if (studentRepository.existsByStudentCodeIgnoreCase(request.getStudentCode().trim())) {
            throw new WebException(ErrorCode.STUDENT_CODE_EXISTS);
        }
        if (!studentClassRepository.existsByClassCodeIgnoreCase(request.getClassCode().trim())) {
            throw new WebException(ErrorCode.STUDENT_CLASS_NOT_FOUND);
        }
    }

    private RuntimeException translateDataIntegrityViolation(
            CreateStudentRequestDTO request,
            DataIntegrityViolationException originalException) {
        if (userRepository.existsByUsernameIgnoreCase(request.getUsername().trim())) {
            return new WebException(ErrorCode.USERNAME_EXISTS);
        }
        if (userRepository.existsByEmailIgnoreCase(request.getEmail().trim())) {
            return new WebException(ErrorCode.EMAIL_EXISTS);
        }
        if (studentRepository.existsByStudentCodeIgnoreCase(request.getStudentCode().trim())) {
            return new WebException(ErrorCode.STUDENT_CODE_EXISTS);
        }
        return originalException;
    }
}
