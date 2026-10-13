package com.zerotrust.risk.domain;

import java.time.Instant;
import java.util.Objects;

public record LoginContext(
        String subjectId,
        String authenticationSessionId,
        String clientId,
        String ipAddress,
        String userAgent,
        String deviceId,
        Instant receivedAt
) {
    public LoginContext {
        subjectId = SubjectIdentifierNormalizer.normalize(subjectId);
        Objects.requireNonNull(authenticationSessionId, "authenticationSessionId must not be null");
        Objects.requireNonNull(clientId, "clientId must not be null");
        Objects.requireNonNull(ipAddress, "ipAddress must not be null");
        Objects.requireNonNull(receivedAt, "receivedAt must not be null");
    }
}
