package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.model.request.CreateStudentRequestDTO;
import com.zerotrust.zerotrust.model.request.UpdateStudentRequestDTO;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.StudentResponseDTO;
import com.zerotrust.zerotrust.service.impl.student.StudentCreationService;
import com.zerotrust.zerotrust.service.impl.student.StudentQueryService;
import com.zerotrust.zerotrust.service.impl.student.StudentUpdateService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StudentAdministrationServiceImplTest {
    @Mock
    private StudentCreationService creationService;
    @Mock
    private StudentUpdateService updateService;
    @Mock
    private StudentQueryService queryService;

    private StudentAdministrationServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new StudentAdministrationServiceImpl(
                creationService,
                updateService,
                queryService);
    }

    @Test
    void delegatesStudentCreation() {
        CreateStudentRequestDTO request = new CreateStudentRequestDTO();
        StudentResponseDTO response = org.mockito.Mockito.mock(StudentResponseDTO.class);
        when(creationService.createStudent(request)).thenReturn(response);

        assertThat(service.createStudent(request)).isSameAs(response);

        verify(creationService).createStudent(request);
    }

    @Test
    void delegatesStudentUpdate() {
        UUID id = UUID.randomUUID();
        UpdateStudentRequestDTO request = new UpdateStudentRequestDTO();
        StudentResponseDTO response = org.mockito.Mockito.mock(StudentResponseDTO.class);
        when(updateService.updateStudent(id, request)).thenReturn(response);

        assertThat(service.updateStudent(id, request)).isSameAs(response);

        verify(updateService).updateStudent(id, request);
    }

    @Test
    void delegatesStudentDetailsQuery() {
        UUID id = UUID.randomUUID();
        StudentResponseDTO response = org.mockito.Mockito.mock(StudentResponseDTO.class);
        when(queryService.getStudent(id)).thenReturn(response);

        assertThat(service.getStudent(id)).isSameAs(response);

        verify(queryService).getStudent(id);
    }

    @Test
    void delegatesStudentListQuery() {
        PageResponse<StudentResponseDTO> response = new PageResponse<>(
                List.of(), 0, 20, 0, 0, true, true);
        when(queryService.getStudents(
                "student", "AT19B", "ACTIVE", 0, 20, "studentCode,asc"))
                .thenReturn(response);

        assertThat(service.getStudents(
                "student", "AT19B", "ACTIVE", 0, 20, "studentCode,asc"))
                .isSameAs(response);

        verify(queryService).getStudents(
                "student", "AT19B", "ACTIVE", 0, 20, "studentCode,asc");
    }
}
