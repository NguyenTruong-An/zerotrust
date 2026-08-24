package com.zerotrust.zerotrust.service;

import com.zerotrust.zerotrust.model.request.CreateStudentRequestDTO;
import com.zerotrust.zerotrust.model.request.UpdateStudentRequestDTO;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.StudentResponseDTO;

import java.util.UUID;

public interface StudentAdministrationService {
    StudentResponseDTO createStudent(CreateStudentRequestDTO request);

    PageResponse<StudentResponseDTO> getStudents(
            String keyword,
            String classCode,
            String status,
            int page,
            int size,
            String sort);

    StudentResponseDTO getStudent(UUID id);

    StudentResponseDTO updateStudent(UUID id, UpdateStudentRequestDTO request);
}
