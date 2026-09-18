package com.zerotrust.risk.service;

import com.zerotrust.risk.repository.AuthenticationFailureStore;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationFailureService {

    private final AuthenticationFailureStore failureStore;

    public boolean recordFailure(String eventId, String subjectId, String sourceIp) {
        return failureStore.recordFailure(
                requireText(eventId, "eventId"),
                optionalText(subjectId),
                requireText(sourceIp, "sourceIp")
        );
    }

    public long countForSubject(String subjectId) {
        return failureStore.countBySubject(requireText(subjectId, "subjectId"));
    }

    public long countForSourceIp(String sourceIp) {
        return failureStore.countBySourceIp(requireText(sourceIp, "sourceIp"));
    }

    private static String optionalText(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value.trim();
    }
}
