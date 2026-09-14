package com.zerotrust.zerotrust.service;

import com.zerotrust.zerotrust.model.request.CreateScoreRequestDTO;
import com.zerotrust.zerotrust.model.request.UpdateScoreRequestDTO;
import com.zerotrust.zerotrust.model.request.UpsertSubjectScoresRequestDTO;
import com.zerotrust.zerotrust.model.response.BatchScoreResponseDTO;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.ScoreResponseDTO;
import com.zerotrust.zerotrust.model.response.SubjectScoreSheetRowResponseDTO;
import com.zerotrust.zerotrust.model.response.StudentScoreSummaryResponseDTO;

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
            String keyword,
            Short semester,
            String academicYear,
            int page,
            int size,
            String sort);

    StudentScoreSummaryResponseDTO getCurrentStudentScoreSummary(UUID keycloakUserId);

    ScoreResponseDTO updateScore(UUID scoreId, UpdateScoreRequestDTO request);

    void deleteScore(UUID scoreId);

    PageResponse<SubjectScoreSheetRowResponseDTO> getSubjectScoreSheet(
            UUID subjectId,
            String classCode,
            String keyword,
            int page,
            int size);

    BatchScoreResponseDTO upsertSubjectScores(
            UUID subjectId,
            UpsertSubjectScoresRequestDTO request);
}
