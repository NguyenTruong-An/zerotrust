package com.zerotrust.zerotrust.service.impl.student;

import com.zerotrust.zerotrust.converter.StudentConverter;
import com.zerotrust.zerotrust.entity.StudentEntity;
import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.response.StudentResponseDTO;
import com.zerotrust.zerotrust.repository.StudentRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StudentQueryServiceTest {
    @Mock
    private StudentRepository studentRepository;
    @Mock
    private StudentConverter studentConverter;

    private StudentQueryService service;

    @BeforeEach
    void setUp() {
        service = new StudentQueryService(studentRepository, studentConverter);
    }

    @Test
    void returnsFilteredPaginatedStudents() {
        StudentEntity student = new StudentEntity();
        StudentResponseDTO response = org.mockito.Mockito.mock(StudentResponseDTO.class);
        when(studentRepository.findAllFiltered(any(), any(), any(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(
                        List.of(student),
                        PageRequest.of(1, 2),
                        3));
        when(studentConverter.convertToDto(student)).thenReturn(response);

        var result = service.getStudents(
                " student01 ",
                " AT19B ",
                " active ",
                1,
                2,
                "username,desc");

        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(studentRepository).findAllFiltered(
                eq("student01"),
                eq("AT19B"),
                eq(UserEntity.Status.ACTIVE),
                pageableCaptor.capture());
        assertThat(pageableCaptor.getValue().getPageNumber()).isEqualTo(1);
        assertThat(pageableCaptor.getValue().getPageSize()).isEqualTo(2);
        assertThat(pageableCaptor.getValue().getSort().getOrderFor("userEntity.username"))
                .extracting(Sort.Order::getDirection)
                .isEqualTo(Sort.Direction.DESC);
        assertThat(result.content()).containsExactly(response);
        assertThat(result.totalElements()).isEqualTo(3);
        assertThat(result.totalPages()).isEqualTo(2);
    }

    @Test
    void returnsStudentDetails() {
        UUID id = UUID.randomUUID();
        StudentEntity student = new StudentEntity();
        StudentResponseDTO response = org.mockito.Mockito.mock(StudentResponseDTO.class);
        when(studentRepository.findDetailedById(id)).thenReturn(Optional.of(student));
        when(studentConverter.convertToDto(student)).thenReturn(response);

        assertThat(service.getStudent(id)).isSameAs(response);
    }

    @Test
    void reportsMissingStudent() {
        UUID id = UUID.randomUUID();
        when(studentRepository.findDetailedById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.getStudent(id))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.STUDENT_NOT_FOUND);
        verify(studentConverter, never()).convertToDto(any());
    }

    @Test
    void rejectsInvalidListParameters() {
        assertThatThrownBy(() -> service.getStudents(
                null, null, null, -1, 20, "studentCode,asc"))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REQUEST);
        assertThatThrownBy(() -> service.getStudents(
                null, null, "SUSPENDED", 0, 20, "studentCode,asc"))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REQUEST);
        assertThatThrownBy(() -> service.getStudents(
                null, null, null, 0, 20, "email,asc"))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REQUEST);

        verify(studentRepository, never()).findAllFiltered(any(), any(), any(), any());
    }
}
