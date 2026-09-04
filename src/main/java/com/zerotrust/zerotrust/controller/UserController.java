package com.zerotrust.zerotrust.controller;

import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.response.ApiResponse;
import com.zerotrust.zerotrust.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(@AuthenticationPrincipal Jwt jwt) {
        UUID keycloakUserId = parseKeycloakUserId(
                jwt == null ? null : jwt.getSubject());
        var currentUser = userService.getCurrentUser(keycloakUserId);
        return ResponseEntity.ok(
                ApiResponse.success(currentUser, "Fetched current user successfully"));
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
