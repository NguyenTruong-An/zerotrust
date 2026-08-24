package com.zerotrust.zerotrust.service;

import com.zerotrust.zerotrust.model.request.CreateScoreRequestDTO;
import com.zerotrust.zerotrust.model.request.UpdateScoreRequestDTO;
import com.zerotrust.zerotrust.model.response.ScoreResponseDTO;

import java.util.UUID;

public interface ScoreAdministrationService {
    ScoreResponseDTO createStudentScore(UUID studentId, CreateScoreRequestDTO request);

    ScoreResponseDTO updateScore(UUID scoreId, UpdateScoreRequestDTO request);
}
