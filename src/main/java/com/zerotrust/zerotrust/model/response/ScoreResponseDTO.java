package com.zerotrust.zerotrust.model.response;

import java.math.BigDecimal;
import java.util.UUID;

public record ScoreResponseDTO(
        UUID id,
        UUID studentId,
        String studentCode,
        UUID subjectId,
        String subjectCode,
        String subjectName,
        Short semester,
        String academicYear,
        BigDecimal attendanceScore,
        BigDecimal midtermScore,
        BigDecimal finalScore,
        BigDecimal totalScore,
        String grade
) {
}
