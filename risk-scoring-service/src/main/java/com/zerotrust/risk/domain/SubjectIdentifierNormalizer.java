package com.zerotrust.risk.domain;

import java.util.Objects;

/** Subject semantics already used by device registration: trim, preserving opaque identity text. */
public final class SubjectIdentifierNormalizer {
    private SubjectIdentifierNormalizer() {}

    public static String normalize(String subjectId) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        if (subjectId.isBlank() || subjectId.length() > 255) {
            throw new IllegalArgumentException("subjectId must contain text and be at most 255 characters");
        }
        String normalized = subjectId.trim();
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("subjectId must contain text");
        }
        return normalized;
    }
}
