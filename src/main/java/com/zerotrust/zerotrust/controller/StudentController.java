package com.zerotrust.zerotrust.controller;

import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.response.ApiResponse;
import com.zerotrust.zerotrust.model.response.PageResponse;
import com.zerotrust.zerotrust.model.response.ScoreResponseDTO;
import com.zerotrust.zerotrust.service.ScoreAdministrationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
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

    @GetMapping("/me/scores")
    public ResponseEntity<ApiResponse<PageResponse<ScoreResponseDTO>>> getCurrentStudentScores(
            @AuthenticationPrincipal OidcUser oidcUser,
            @RequestParam(required = false) UUID subjectId,
            @RequestParam(required = false) Short semester,
            @RequestParam(required = false) String academicYear,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "academicYear,desc") String sort) {
        UUID keycloakUserId = parseKeycloakUserId(
                oidcUser == null ? null : oidcUser.getSubject());
        PageResponse<ScoreResponseDTO> scores =
                scoreAdministrationService.getCurrentStudentScores(
                        keycloakUserId,
                        subjectId,
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
