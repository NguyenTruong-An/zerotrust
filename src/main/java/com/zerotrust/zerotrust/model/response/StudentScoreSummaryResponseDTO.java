package com.zerotrust.zerotrust.model.response;

import java.math.BigDecimal;

public record StudentScoreSummaryResponseDTO(
        long totalSubjects,
        long completedSubjects,
        long passedSubjects,
        long failedSubjects,
        BigDecimal averageScore,
        BigDecimal highestScore,
        Short latestSemester,
        String latestAcademicYear
) {
}
