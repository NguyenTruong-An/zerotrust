package com.zerotrust.zerotrust.model.response;

import java.util.UUID;

public record StudentClassResponseDTO(
        UUID id,
        String classCode,
        String className,
        String department,
        String academicYear
) {
}
