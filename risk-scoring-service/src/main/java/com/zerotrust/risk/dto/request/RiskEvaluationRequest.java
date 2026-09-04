package com.zerotrust.risk.dto.request;

import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.validation.ValidIpAddress;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.time.Instant;

public record RiskEvaluationRequest(
        @NotBlank @Size(max = 255) String subjectId,
        @NotBlank @Size(max = 255) String authenticationSessionId,
        @NotBlank @Size(max = 255) String clientId,
        @NotBlank @Size(max = 45) @ValidIpAddress String ipAddress,
        @Size(max = 1024) String userAgent,
        @Size(max = 255) String deviceId
) {
    public LoginContext toDomain(Instant receivedAt) {
        return new LoginContext(
                subjectId,
                authenticationSessionId,
                clientId,
                ipAddress,
                userAgent,
                deviceId,
                receivedAt
        );
    }
}
