package com.zerotrust.zerotrust.service;

import com.zerotrust.zerotrust.model.request.CreateScoreRequestDTO;
import com.zerotrust.zerotrust.model.request.UpdateScoreRequestDTO;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.ScoreResponseDTO;

import java.util.UUID;

public interface ScoreAdministrationService {
    ScoreResponseDTO createStudentScore(UUID studentId, CreateScoreRequestDTO request);

    PageResponse<ScoreResponseDTO> getStudentScores(
            UUID studentId,
            UUID subjectId,
            Short semester,
            String academicYear,
            int page,
            int size,
            String sort);

    PageResponse<ScoreResponseDTO> getCurrentStudentScores(
            UUID keycloakUserId,
            UUID subjectId,
            Short semester,
            String academicYear,
            int page,
            int size,
            String sort);

    ScoreResponseDTO updateScore(UUID scoreId, UpdateScoreRequestDTO request);
}
