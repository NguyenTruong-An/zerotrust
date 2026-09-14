package com.zerotrust.zerotrust.service;

import com.zerotrust.zerotrust.model.request.CreateStudentClassRequestDTO;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.StudentClassResponseDTO;

import java.util.UUID;

public interface StudentClassAdministrationService {
    StudentClassResponseDTO createStudentClass(CreateStudentClassRequestDTO request);

    void deleteStudentClass(UUID classId);

    PageResponse<StudentClassResponseDTO> getStudentClasses(
            String keyword,
            String department,
            String courseYears,
            int page,
            int size,
            String sort);
}
