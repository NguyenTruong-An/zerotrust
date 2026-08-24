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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StudentUpdateServiceTest {
    @Mock
    private UserRepository userRepository;
    @Mock
    private StudentRepository studentRepository;
    @Mock
    private StudentClassRepository studentClassRepository;
    @Mock
    private IdentityProviderGateway identityProviderGateway;
    @Mock
    private StudentPersistenceService studentPersistenceService;

    private StudentUpdateService service;

    @BeforeEach
    void setUp() {
        service = new StudentUpdateService(
                userRepository,
                studentRepository,
                studentClassRepository,
                identityProviderGateway,
                studentPersistenceService);
    }

    @Test
    void updatesIdentityProfileAndStudentDatabase() {
        UUID studentId = UUID.randomUUID();
        UUID identityUserId = UUID.randomUUID();
        StudentEntity student = student(identityUserId, "An", "Nguyen");
        UpdateStudentRequestDTO request = UpdateStudentRequestDTO.builder()
                .email(" Updated.Student@Example.com ")
                .firstName(" Truong An ")
                .phone("0987000000")
                .build();
        StudentResponseDTO response = org.mockito.Mockito.mock(StudentResponseDTO.class);
        IdentityUserProfileSnapshot snapshot = new IdentityUserProfileSnapshot(
                "An", "Nguyen", "student01@example.com", true);
        when(studentRepository.findDetailedById(studentId)).thenReturn(Optional.of(student));
        when(identityProviderGateway.updateUserProfile(
                identityUserId,
                "Truong An",
                "Nguyen",
                "updated.student@example.com"))
                .thenReturn(snapshot);
        when(studentPersistenceService.updateStudent(studentId, request)).thenReturn(response);

        assertThat(service.updateStudent(studentId, request)).isSameAs(response);

        verify(identityProviderGateway).updateUserProfile(
                identityUserId,
                "Truong An",
                "Nguyen",
                "updated.student@example.com");
        verify(identityProviderGateway, never())
                .restoreUserProfileQuietly(identityUserId, snapshot);
    }

    @Test
    void updatesStudentOnlyFieldsWithoutCallingIdentityProvider() {
        UUID studentId = UUID.randomUUID();
        StudentEntity student = student(UUID.randomUUID(), "An", "Nguyen");
        UpdateStudentRequestDTO request = UpdateStudentRequestDTO.builder()
                .studentCode("SV002")
                .build();
        StudentResponseDTO response = org.mockito.Mockito.mock(StudentResponseDTO.class);
        when(studentRepository.findDetailedById(studentId)).thenReturn(Optional.of(student));
        when(studentPersistenceService.updateStudent(studentId, request)).thenReturn(response);

        assertThat(service.updateStudent(studentId, request)).isSameAs(response);

        verify(identityProviderGateway, never()).updateUserProfile(any(), any(), any(), any());
        verify(identityProviderGateway, never()).restoreUserProfileQuietly(any(), any());
    }

    @Test
    void restoresIdentityProfileWhenDatabaseUpdateFails() {
        UUID studentId = UUID.randomUUID();
        UUID identityUserId = UUID.randomUUID();
        StudentEntity student = student(identityUserId, "An", "Nguyen");
        UpdateStudentRequestDTO request = UpdateStudentRequestDTO.builder()
                .email("new.student@example.com")
                .lastName("Tran")
                .build();
        RuntimeException databaseException = new RuntimeException("database unavailable");
        IdentityUserProfileSnapshot snapshot = new IdentityUserProfileSnapshot(
                "An", "Nguyen", "student01@example.com", true);
        when(studentRepository.findDetailedById(studentId)).thenReturn(Optional.of(student));
        when(identityProviderGateway.updateUserProfile(
                identityUserId,
                "An",
                "Tran",
                "new.student@example.com"))
                .thenReturn(snapshot);
        when(studentPersistenceService.updateStudent(studentId, request))
                .thenThrow(databaseException);

        assertThatThrownBy(() -> service.updateStudent(studentId, request))
                .isSameAs(databaseException);
        verify(identityProviderGateway)
                .restoreUserProfileQuietly(identityUserId, snapshot);
    }

    @Test
    void rejectsUpdateWithoutAnyFields() {
        UUID studentId = UUID.randomUUID();

        assertThatThrownBy(() -> service.updateStudent(
                studentId, new UpdateStudentRequestDTO()))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REQUEST);

        verify(studentRepository, never()).findDetailedById(any());
        verify(studentPersistenceService, never()).updateStudent(any(), any());
    }

    @Test
    void rejectsDuplicateStudentCodeBeforeUpdatingStudent() {
        UUID studentId = UUID.randomUUID();
        UpdateStudentRequestDTO request = UpdateStudentRequestDTO.builder()
                .studentCode("SV002")
                .build();
        when(studentRepository.findDetailedById(studentId))
                .thenReturn(Optional.of(student(UUID.randomUUID(), "An", "Nguyen")));
        when(studentRepository.existsByStudentCodeIgnoreCaseAndIdNot("SV002", studentId))
                .thenReturn(true);

        assertThatThrownBy(() -> service.updateStudent(studentId, request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.STUDENT_CODE_EXISTS);

        verify(studentPersistenceService, never()).updateStudent(any(), any());
        verify(identityProviderGateway, never()).updateUserProfile(any(), any(), any(), any());
    }

    @Test
    void rejectsDuplicateEmailBeforeUpdatingStudent() {
        UUID studentId = UUID.randomUUID();
        StudentEntity student = student(UUID.randomUUID(), "An", "Nguyen");
        UpdateStudentRequestDTO request = UpdateStudentRequestDTO.builder()
                .email(" existing@example.com ")
                .build();
        when(studentRepository.findDetailedById(studentId)).thenReturn(Optional.of(student));
        when(userRepository.existsByEmailIgnoreCaseAndIdNot(
                "existing@example.com", student.getUserEntity().getId()))
                .thenReturn(true);

        assertThatThrownBy(() -> service.updateStudent(studentId, request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.EMAIL_EXISTS);

        verify(studentPersistenceService, never()).updateStudent(any(), any());
        verify(identityProviderGateway, never()).updateUserProfile(any(), any(), any(), any());
    }

    private StudentEntity student(
            UUID identityUserId,
            String firstName,
            String lastName) {
        UserEntity user = new UserEntity();
        user.setId(UUID.randomUUID());
        user.setKeycloakUserId(identityUserId);
        user.setEmail("student01@example.com");
        user.setFirstName(firstName);
        user.setLastName(lastName);
        StudentEntity student = new StudentEntity();
        student.setUserEntity(user);
        return student;
    }
}
