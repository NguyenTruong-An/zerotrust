package com.zerotrust.zerotrust.service;

import com.zerotrust.zerotrust.model.request.CreateSubjectRequestDTO;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.SubjectResponseDTO;

public interface SubjectAdministrationService {
    SubjectResponseDTO createSubject(CreateSubjectRequestDTO request);

    PageResponse<SubjectResponseDTO> getSubjects(
            String keyword,
            int page,
            int size,
            String sort);
}
