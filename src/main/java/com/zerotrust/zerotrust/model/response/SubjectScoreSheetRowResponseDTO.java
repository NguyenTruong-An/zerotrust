package com.zerotrust.zerotrust.model.response;

import java.math.BigDecimal;
import java.util.UUID;

public record SubjectScoreSheetRowResponseDTO(
        UUID scoreId,
        UUID studentId,
        String studentCode,
        String firstName,
        String lastName,
        String classCode,
        String className,
        Short semester,
        String academicYear,
        BigDecimal attendanceScore,
        BigDecimal midtermScore,
        BigDecimal finalScore,
        BigDecimal totalScore,
        String grade
) {
}
