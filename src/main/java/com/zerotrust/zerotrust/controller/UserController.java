package com.zerotrust.zerotrust.controller;

import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.request.RegisterRequestDTO;
import com.zerotrust.zerotrust.model.request.UpdateProfileRequestDTO;
import com.zerotrust.zerotrust.model.response.ApiResponse;
import com.zerotrust.zerotrust.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequestDTO registerRequestDTO) {
        var registeredUser = userService.register(registerRequestDTO);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success(registeredUser, "User registered successfully"));
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(@AuthenticationPrincipal Jwt jwt) {
        UUID keycloakUserId = parseKeycloakUserId(jwt.getSubject());
        var currentUser = userService.getCurrentUser(keycloakUserId);
        return ResponseEntity.ok(
                ApiResponse.success(currentUser, "Fetched current user successfully"));
    }

    @PatchMapping("/me")
    public ResponseEntity<?> updateCurrentUser(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody UpdateProfileRequestDTO request) {
        UUID keycloakUserId = parseKeycloakUserId(jwt.getSubject());
        var updatedUser = userService.updateCurrentUser(keycloakUserId, request);
        return ResponseEntity.ok(
                ApiResponse.success(updatedUser, "Updated current user successfully"));
    }

    @GetMapping("/all-users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getAllUsers() {
        return ResponseEntity.ok(ApiResponse.success(userService.getAllUsers(), "Fetched all users successfully"));
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
