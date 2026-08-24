package com.zerotrust.zerotrust.service.impl.student;

import com.zerotrust.zerotrust.converter.StudentConverter;
import com.zerotrust.zerotrust.entity.StudentClassEntity;
import com.zerotrust.zerotrust.entity.StudentEntity;
import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.model.request.CreateStudentRequestDTO;
import com.zerotrust.zerotrust.model.request.UpdateStudentRequestDTO;
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

import java.time.LocalDate;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StudentPersistenceServiceTest {
    @Mock
    private UserRepository userRepository;
    @Mock
    private StudentRepository studentRepository;
    @Mock
    private StudentClassRepository studentClassRepository;
    @Mock
    private StudentConverter studentConverter;

    private StudentPersistenceService service;

    @BeforeEach
    void setUp() {
        service = new StudentPersistenceService(
                userRepository,
                studentRepository,
                studentClassRepository,
                studentConverter);
    }

    @Test
    void savesLinkedUserAndStudentInTheSameOperation() {
        CreateStudentRequestDTO request = request();
        UUID identityUserId = UUID.randomUUID();
        StudentClassEntity studentClass = new StudentClassEntity();
        StudentResponseDTO response = org.mockito.Mockito.mock(StudentResponseDTO.class);
        when(studentClassRepository.findByClassCodeIgnoreCase(request.getClassCode()))
                .thenReturn(Optional.of(studentClass));
        when(userRepository.saveAndFlush(any(UserEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(studentRepository.saveAndFlush(any(StudentEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(studentConverter.convertToDto(any(StudentEntity.class))).thenReturn(response);

        assertThat(service.saveStudent(identityUserId, request)).isSameAs(response);

        ArgumentCaptor<UserEntity> userCaptor = ArgumentCaptor.forClass(UserEntity.class);
        ArgumentCaptor<StudentEntity> studentCaptor = ArgumentCaptor.forClass(StudentEntity.class);
        verify(userRepository).saveAndFlush(userCaptor.capture());
        verify(studentRepository).saveAndFlush(studentCaptor.capture());
        assertThat(userCaptor.getValue().getKeycloakUserId()).isEqualTo(identityUserId);
        assertThat(userCaptor.getValue().getEmail()).isEqualTo("student01@example.com");
        assertThat(studentCaptor.getValue().getUserEntity()).isSameAs(userCaptor.getValue());
        assertThat(studentCaptor.getValue().getStudentClassEntity()).isSameAs(studentClass);
        assertThat(studentCaptor.getValue().getStudentCode()).isEqualTo("SV001");
    }

    @Test
    void updatesProvidedStudentProfileFields() {
        UUID studentId = UUID.randomUUID();
        UserEntity user = new UserEntity();
        user.setFirstName("An");
        user.setLastName("Nguyen");
        StudentClassEntity currentClass = new StudentClassEntity();
        StudentClassEntity updatedClass = new StudentClassEntity();
        StudentEntity student = new StudentEntity();
        student.setUserEntity(user);
        student.setStudentClassEntity(currentClass);
        student.setStudentCode("SV001");
        student.setPhone("0987654321");
        StudentResponseDTO response = org.mockito.Mockito.mock(StudentResponseDTO.class);
        UpdateStudentRequestDTO request = UpdateStudentRequestDTO.builder()
                .email(" New.Student@Example.COM ")
                .firstName(" Truong An ")
                .studentCode(" sv002 ")
                .dateOfBirth(LocalDate.of(2003, 8, 10))
                .gender("female")
                .phone(" ")
                .address(" Ha Noi ")
                .classCode("AT19C")
                .build();
        when(studentRepository.findDetailedById(studentId)).thenReturn(Optional.of(student));
        when(studentClassRepository.findByClassCodeIgnoreCase("AT19C"))
                .thenReturn(Optional.of(updatedClass));
        when(studentRepository.saveAndFlush(student)).thenReturn(student);
        when(studentConverter.convertToDto(student)).thenReturn(response);

        assertThat(service.updateStudent(studentId, request)).isSameAs(response);

        assertThat(user.getFirstName()).isEqualTo("Truong An");
        assertThat(user.getLastName()).isEqualTo("Nguyen");
        assertThat(user.getEmail()).isEqualTo("new.student@example.com");
        assertThat(student.getStudentCode()).isEqualTo("SV002");
        assertThat(student.getDateOfBirth()).isEqualTo(LocalDate.of(2003, 8, 10));
        assertThat(student.getGender()).isEqualTo("FEMALE");
        assertThat(student.getPhone()).isNull();
        assertThat(student.getAddress()).isEqualTo("Ha Noi");
        assertThat(student.getStudentClassEntity()).isSameAs(updatedClass);
        verify(studentRepository).saveAndFlush(student);
    }

    private CreateStudentRequestDTO request() {
        return CreateStudentRequestDTO.builder()
                .username(" student01 ")
                .password("Temp@123456")
                .email(" Student01@Example.com ")
                .firstName(" An ")
                .lastName(" Nguyen ")
                .studentCode(" sv001 ")
                .dateOfBirth(LocalDate.of(2003, 5, 20))
                .gender("male")
                .phone(" 0987654321 ")
                .address(" Ha Noi ")
                .classCode("AT19B")
                .build();
    }
}
