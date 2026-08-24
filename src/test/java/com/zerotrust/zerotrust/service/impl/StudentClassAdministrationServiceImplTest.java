package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.entity.StudentClassEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.request.CreateStudentClassRequestDTO;
import com.zerotrust.zerotrust.repository.StudentClassRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StudentClassAdministrationServiceImplTest {
    @Mock
    private StudentClassRepository studentClassRepository;

    private StudentClassAdministrationServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new StudentClassAdministrationServiceImpl(studentClassRepository);
    }

    @Test
    void createsNormalizedStudentClass() {
        CreateStudentClassRequestDTO request = request(" at19b ", "2022-2026");
        when(studentClassRepository.saveAndFlush(any(StudentClassEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        var response = service.createStudentClass(request);

        ArgumentCaptor<StudentClassEntity> entityCaptor =
                ArgumentCaptor.forClass(StudentClassEntity.class);
        verify(studentClassRepository).saveAndFlush(entityCaptor.capture());
        assertThat(entityCaptor.getValue().getClassCode()).isEqualTo("AT19B");
        assertThat(response.classCode()).isEqualTo("AT19B");
        assertThat(response.academicYear()).isEqualTo("2022-2026");
    }

    @Test
    void rejectsDuplicateClassCode() {
        CreateStudentClassRequestDTO request = request("AT19B", "2022-2026");
        when(studentClassRepository.existsByClassCodeIgnoreCase("AT19B")).thenReturn(true);

        assertThatThrownBy(() -> service.createStudentClass(request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.STUDENT_CLASS_CODE_EXISTS);
        verify(studentClassRepository, never()).saveAndFlush(any());
    }

    @Test
    void rejectsAcademicYearWhoseEndIsNotLater() {
        CreateStudentClassRequestDTO request = request("AT19B", "2026-2022");

        assertThatThrownBy(() -> service.createStudentClass(request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REQUEST);
        verify(studentClassRepository, never()).saveAndFlush(any());
    }

    @Test
    void returnsFilteredPaginatedStudentClasses() {
        StudentClassEntity studentClass = new StudentClassEntity();
        UUID id = UUID.randomUUID();
        studentClass.setId(id);
        studentClass.setClassCode("AT19B");
        studentClass.setClassName("An toan thong tin 19B");
        studentClass.setDepartment("An toan thong tin");
        studentClass.setAcademicYear("2022-2026");
        when(studentClassRepository.findAllFiltered(
                any(), any(), any(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(studentClass)));

        var response = service.getStudentClasses(
                " AT19 ",
                " An toan thong tin ",
                " 2022-2026 ",
                0,
                20,
                "classCode,desc");

        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(studentClassRepository).findAllFiltered(
                org.mockito.ArgumentMatchers.eq("AT19"),
                org.mockito.ArgumentMatchers.eq("An toan thong tin"),
                org.mockito.ArgumentMatchers.eq("2022-2026"),
                pageableCaptor.capture());
        assertThat(pageableCaptor.getValue().getPageNumber()).isZero();
        assertThat(pageableCaptor.getValue().getPageSize()).isEqualTo(20);
        assertThat(pageableCaptor.getValue().getSort().getOrderFor("classCode"))
                .extracting(Sort.Order::getDirection)
                .isEqualTo(Sort.Direction.DESC);
        assertThat(response.content()).singleElement().satisfies(result -> {
            assertThat(result.id()).isEqualTo(id);
            assertThat(result.classCode()).isEqualTo("AT19B");
        });
    }

    @Test
    void rejectsInvalidPaginationAndSort() {
        assertThatThrownBy(() -> service.getStudentClasses(
                null, null, null, -1, 20, "classCode,asc"))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REQUEST);
        assertThatThrownBy(() -> service.getStudentClasses(
                null, null, null, 0, 101, "classCode,asc"))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REQUEST);
        assertThatThrownBy(() -> service.getStudentClasses(
                null, null, null, 0, 20, "createdAt,desc"))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REQUEST);

        verify(studentClassRepository, never()).findAllFiltered(any(), any(), any(), any());
    }

    private CreateStudentClassRequestDTO request(String classCode, String academicYear) {
        return CreateStudentClassRequestDTO.builder()
                .classCode(classCode)
                .className("An toan thong tin 19B")
                .department("An toan thong tin")
                .academicYear(academicYear)
                .build();
    }
}
