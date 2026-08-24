package com.zerotrust.zerotrust.model.response;

import java.util.UUID;

public record SubjectResponseDTO(
        UUID id,
        String subjectCode,
        String subjectName,
        Short credits,
        String description
) {
}
