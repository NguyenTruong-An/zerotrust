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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;

import java.time.LocalDate;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StudentCreationServiceTest {
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

    private StudentCreationService service;

    @BeforeEach
    void setUp() {
        service = new StudentCreationService(
                userRepository,
                studentRepository,
                studentClassRepository,
                identityProviderGateway,
                studentPersistenceService);
    }

    @Test
    void createsIdentityAccountAssignsStudentRoleAndPersistsStudent() {
        CreateStudentRequestDTO request = validRequest();
        UUID identityUserId = UUID.randomUUID();
        ProvisionedIdentityUser provisionedUser = new ProvisionedIdentityUser(identityUserId);
        StudentResponseDTO response = org.mockito.Mockito.mock(StudentResponseDTO.class);
        when(studentClassRepository.existsByClassCodeIgnoreCase(request.getClassCode()))
                .thenReturn(true);
        when(identityProviderGateway.createUser(any())).thenReturn(provisionedUser);
        when(studentPersistenceService.saveStudent(identityUserId, request)).thenReturn(response);

        assertThat(service.createStudent(request)).isSameAs(response);

        ArgumentCaptor<CreateIdentityUserCommand> commandCaptor =
                ArgumentCaptor.forClass(CreateIdentityUserCommand.class);
        verify(identityProviderGateway).createUser(commandCaptor.capture());
        assertThat(commandCaptor.getValue().username()).isEqualTo("student01");
        assertThat(commandCaptor.getValue().password()).isEqualTo("Temp@123456");
        verify(identityProviderGateway).assignRealmRole(identityUserId, "STUDENT");
        verify(identityProviderGateway, never()).deleteUserQuietly(provisionedUser);
    }

    @Test
    void rejectsUnknownStudentClassBeforeCreatingIdentityAccount() {
        CreateStudentRequestDTO request = validRequest();
        when(studentClassRepository.existsByClassCodeIgnoreCase(request.getClassCode()))
                .thenReturn(false);

        assertThatThrownBy(() -> service.createStudent(request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.STUDENT_CLASS_NOT_FOUND);
        verify(identityProviderGateway, never()).createUser(any());
    }

    @Test
    void rejectsDuplicateStudentCodeBeforeCreatingIdentityAccount() {
        CreateStudentRequestDTO request = validRequest();
        when(studentRepository.existsByStudentCodeIgnoreCase(request.getStudentCode()))
                .thenReturn(true);

        assertThatThrownBy(() -> service.createStudent(request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.STUDENT_CODE_EXISTS);
        verify(identityProviderGateway, never()).createUser(any());
    }

    @Test
    void deletesIdentityUserWhenRoleAssignmentFails() {
        CreateStudentRequestDTO request = validRequest();
        UUID identityUserId = UUID.randomUUID();
        ProvisionedIdentityUser provisionedUser = new ProvisionedIdentityUser(identityUserId);
        WebException roleException = new WebException(ErrorCode.IDENTITY_ROLE_NOT_FOUND);
        when(studentClassRepository.existsByClassCodeIgnoreCase(request.getClassCode()))
                .thenReturn(true);
        when(identityProviderGateway.createUser(any())).thenReturn(provisionedUser);
        org.mockito.Mockito.doThrow(roleException)
                .when(identityProviderGateway)
                .assignRealmRole(identityUserId, "STUDENT");

        assertThatThrownBy(() -> service.createStudent(request)).isSameAs(roleException);
        verify(identityProviderGateway).deleteUserQuietly(provisionedUser);
        verify(studentPersistenceService, never()).saveStudent(any(), any());
    }

    @Test
    void deletesIdentityUserWhenDatabaseTransactionFails() {
        CreateStudentRequestDTO request = validRequest();
        UUID identityUserId = UUID.randomUUID();
        ProvisionedIdentityUser provisionedUser = new ProvisionedIdentityUser(identityUserId);
        DataIntegrityViolationException databaseException =
                new DataIntegrityViolationException("constraint violation");
        when(studentClassRepository.existsByClassCodeIgnoreCase(request.getClassCode()))
                .thenReturn(true);
        when(identityProviderGateway.createUser(any())).thenReturn(provisionedUser);
        when(studentPersistenceService.saveStudent(identityUserId, request))
                .thenThrow(databaseException);

        assertThatThrownBy(() -> service.createStudent(request)).isSameAs(databaseException);
        verify(identityProviderGateway).deleteUserQuietly(provisionedUser);
    }

    private CreateStudentRequestDTO validRequest() {
        return CreateStudentRequestDTO.builder()
                .username("student01")
                .password("Temp@123456")
                .email("student01@example.com")
                .firstName("An")
                .lastName("Nguyen")
                .studentCode("SV001")
                .dateOfBirth(LocalDate.of(2003, 5, 20))
                .gender("MALE")
                .phone("0987654321")
                .address("Ha Noi")
                .classCode("AT19B")
                .build();
    }
}
