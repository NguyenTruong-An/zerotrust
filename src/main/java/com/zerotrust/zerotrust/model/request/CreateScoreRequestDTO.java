package com.zerotrust.zerotrust.model.request;

import com.zerotrust.zerotrust.model.validation.ScoreValue;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateScoreRequestDTO {
    @NotNull(message = "Subject ID is required")
    private UUID subjectId;

    @NotNull(message = "Semester is required")
    @Min(value = 1, message = "Semester must be at least 1")
    @Max(value = 2, message = "Semester must not exceed 2")
    private Short semester;

    @NotBlank(message = "Academic year is required")
    @Pattern(
            regexp = "^\\d{4}-\\d{4}$",
            message = "Academic year must use the format YYYY-YYYY")
    private String academicYear;

    @ScoreValue(
            minMessage = "Attendance score must be at least 0",
            maxMessage = "Attendance score must not exceed 10",
            precisionMessage = "Attendance score must have at most 2 decimal places")
    @NotNull(message = "Attendance score is required")
    private BigDecimal attendanceScore;

    @ScoreValue(
            minMessage = "Midterm score must be at least 0",
            maxMessage = "Midterm score must not exceed 10",
            precisionMessage = "Midterm score must have at most 2 decimal places")
    @NotNull(message = "Midterm score is required")
    private BigDecimal midtermScore;

    @ScoreValue(
            minMessage = "Final score must be at least 0",
            maxMessage = "Final score must not exceed 10",
            precisionMessage = "Final score must have at most 2 decimal places")
    @NotNull(message = "Final score is required")
    private BigDecimal finalScore;
}
