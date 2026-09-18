package com.zerotrust.risk.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.Instant;

public record AuthenticationSuccessRequest(
        @NotBlank @Size(max = 255) String eventId,
        @NotBlank @Size(max = 255) String subjectId,
        @NotBlank @Size(max = 255) String clientId,
        @NotNull Instant authenticatedAt
) {
}
