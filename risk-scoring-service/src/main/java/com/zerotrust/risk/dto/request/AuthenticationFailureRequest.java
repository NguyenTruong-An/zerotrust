package com.zerotrust.risk.dto.request;

import com.zerotrust.risk.validation.ValidIpAddress;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record AuthenticationFailureRequest(
        @NotBlank @Size(max = 255) String eventId,
        @Size(max = 255) String subjectId,
        @NotBlank @Size(max = 45) @ValidIpAddress String sourceIp
) {
}
