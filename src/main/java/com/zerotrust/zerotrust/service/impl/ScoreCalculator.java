package com.zerotrust.zerotrust.service.impl;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Objects;

final class ScoreCalculator {
    private static final BigDecimal COURSEWORK_WEIGHT = new BigDecimal("0.30");
    private static final BigDecimal FINAL_WEIGHT = new BigDecimal("0.70");
    private static final BigDecimal ATTENDANCE_WEIGHT = new BigDecimal("0.30");
    private static final BigDecimal MIDTERM_WEIGHT = new BigDecimal("0.70");

    private ScoreCalculator() {
    }

    static Result calculate(
            BigDecimal attendanceScore,
            BigDecimal midtermScore,
            BigDecimal finalScore) {
        Objects.requireNonNull(attendanceScore, "Attendance score is required");
        Objects.requireNonNull(midtermScore, "Midterm score is required");
        Objects.requireNonNull(finalScore, "Final score is required");

        BigDecimal courseworkScore = midtermScore.multiply(MIDTERM_WEIGHT)
                .add(attendanceScore.multiply(ATTENDANCE_WEIGHT));
        BigDecimal totalScore = courseworkScore.multiply(COURSEWORK_WEIGHT)
                .add(finalScore.multiply(FINAL_WEIGHT))
                .setScale(1, RoundingMode.HALF_UP);

        return new Result(totalScore, gradeFor(totalScore));
    }

    static String gradeFor(BigDecimal totalScore) {
        BigDecimal roundedScore = totalScore.setScale(1, RoundingMode.HALF_UP);
        if (roundedScore.compareTo(new BigDecimal("9.0")) >= 0) return "A+";
        if (roundedScore.compareTo(new BigDecimal("8.5")) >= 0) return "A";
        if (roundedScore.compareTo(new BigDecimal("7.8")) >= 0) return "B+";
        if (roundedScore.compareTo(new BigDecimal("7.0")) >= 0) return "B";
        if (roundedScore.compareTo(new BigDecimal("6.3")) >= 0) return "C+";
        if (roundedScore.compareTo(new BigDecimal("5.5")) >= 0) return "C";
        if (roundedScore.compareTo(new BigDecimal("4.8")) >= 0) return "D+";
        if (roundedScore.compareTo(new BigDecimal("4.0")) >= 0) return "D";
        return "F";
    }

    record Result(BigDecimal totalScore, String grade) {
    }
}
