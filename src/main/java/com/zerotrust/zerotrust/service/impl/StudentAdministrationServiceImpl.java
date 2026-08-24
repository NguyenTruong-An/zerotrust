package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.model.request.CreateStudentRequestDTO;
import com.zerotrust.zerotrust.model.request.UpdateStudentRequestDTO;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.StudentResponseDTO;
import com.zerotrust.zerotrust.service.StudentAdministrationService;
import com.zerotrust.zerotrust.service.impl.student.StudentCreationService;
import com.zerotrust.zerotrust.service.impl.student.StudentQueryService;
import com.zerotrust.zerotrust.service.impl.student.StudentUpdateService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class StudentAdministrationServiceImpl implements StudentAdministrationService {
    private final StudentCreationService creationService;
    private final StudentUpdateService updateService;
    private final StudentQueryService queryService;

    @Override
    public StudentResponseDTO createStudent(CreateStudentRequestDTO request) {
        return creationService.createStudent(request);
    }

    @Override
    public PageResponse<StudentResponseDTO> getStudents(
            String keyword,
            String classCode,
            String status,
            int page,
            int size,
            String sort) {
        return queryService.getStudents(keyword, classCode, status, page, size, sort);
    }

    @Override
    public StudentResponseDTO getStudent(UUID id) {
        return queryService.getStudent(id);
    }

    @Override
    public StudentResponseDTO updateStudent(UUID id, UpdateStudentRequestDTO request) {
        return updateService.updateStudent(id, request);
    }
}
