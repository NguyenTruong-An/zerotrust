package com.zerotrust.zerotrust.service;

import com.zerotrust.zerotrust.model.request.CreateStudentClassRequestDTO;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.StudentClassResponseDTO;

public interface StudentClassAdministrationService {
    StudentClassResponseDTO createStudentClass(CreateStudentClassRequestDTO request);

    PageResponse<StudentClassResponseDTO> getStudentClasses(
            String keyword,
            String department,
            String academicYear,
            int page,
            int size,
            String sort);
}
