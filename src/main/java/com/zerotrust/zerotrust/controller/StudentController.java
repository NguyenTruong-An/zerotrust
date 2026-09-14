package com.zerotrust.zerotrust.controller;

import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.response.ApiResponse;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.ScoreResponseDTO;
import com.zerotrust.zerotrust.model.response.StudentResponseDTO;
import com.zerotrust.zerotrust.model.response.StudentScoreSummaryResponseDTO;
import com.zerotrust.zerotrust.service.ScoreAdministrationService;
import com.zerotrust.zerotrust.service.impl.student.StudentQueryService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/students")
@RequiredArgsConstructor
@PreAuthorize("hasRole('STUDENT')")
public class StudentController {
    private final ScoreAdministrationService scoreAdministrationService;
    private final StudentQueryService studentQueryService;

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<StudentResponseDTO>> getCurrentStudent(
            @AuthenticationPrincipal Jwt jwt) {
        UUID keycloakUserId = parseKeycloakUserId(jwt == null ? null : jwt.getSubject());
        return ResponseEntity.ok(ApiResponse.success(
                studentQueryService.getCurrentStudent(keycloakUserId),
                "Fetched current student successfully"));
    }

    @GetMapping("/me/scores/summary")
    public ResponseEntity<ApiResponse<StudentScoreSummaryResponseDTO>>
            getCurrentStudentScoreSummary(@AuthenticationPrincipal Jwt jwt) {
        UUID keycloakUserId = parseKeycloakUserId(jwt == null ? null : jwt.getSubject());
        return ResponseEntity.ok(ApiResponse.success(
                scoreAdministrationService.getCurrentStudentScoreSummary(keycloakUserId),
                "Fetched current student score summary successfully"));
    }

    @GetMapping("/me/scores")
    public ResponseEntity<ApiResponse<PageResponse<ScoreResponseDTO>>> getCurrentStudentScores(
            @AuthenticationPrincipal Jwt jwt,
            @RequestParam(required = false) UUID subjectId,
            @RequestParam(required = false) String keyword,
            @RequestParam(required = false) Short semester,
            @RequestParam(required = false) String academicYear,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "academicYear,desc") String sort) {
        UUID keycloakUserId = parseKeycloakUserId(
                jwt == null ? null : jwt.getSubject());
        PageResponse<ScoreResponseDTO> scores =
                scoreAdministrationService.getCurrentStudentScores(
                        keycloakUserId,
                        subjectId,
                        keyword,
                        semester,
                        academicYear,
                        page,
                        size,
                        sort);
        return ResponseEntity.ok(
                ApiResponse.success(scores, "Fetched current student scores successfully"));
    }

    private UUID parseKeycloakUserId(String subject) {
        if (subject == null) {
            throw new WebException(ErrorCode.UNAUTHORIZED);
        }

        try {
            return UUID.fromString(subject);
        } catch (IllegalArgumentException ex) {
            throw new WebException(ErrorCode.UNAUTHORIZED);
        }
    }
}
