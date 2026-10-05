package com.zerotrust.risk.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record TrustedDeviceRegistrationRequest(
        @NotBlank @Size(max = 255) String subjectId,
        @NotBlank @Size(max = 255) String deviceId,
        @jakarta.validation.constraints.NotNull @jakarta.validation.constraints.PositiveOrZero Long trustGeneration
) {
}
