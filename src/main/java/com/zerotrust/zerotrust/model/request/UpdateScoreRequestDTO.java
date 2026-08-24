package com.zerotrust.zerotrust.model.request;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Digits;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
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
public class UpdateScoreRequestDTO {
    private UUID subjectId;

    @Min(value = 1, message = "Semester must be at least 1")
    @Max(value = 3, message = "Semester must not exceed 3")
    private Short semester;

    @Pattern(
            regexp = "^\\d{4}-\\d{4}$",
            message = "Academic year must use the format YYYY-YYYY")
    private String academicYear;

    @DecimalMin(value = "0.0", message = "Attendance score must be at least 0")
    @DecimalMax(value = "10.0", message = "Attendance score must not exceed 10")
    @Digits(integer = 2, fraction = 2, message = "Attendance score must have at most 2 decimal places")
    private BigDecimal attendanceScore;

    @DecimalMin(value = "0.0", message = "Midterm score must be at least 0")
    @DecimalMax(value = "10.0", message = "Midterm score must not exceed 10")
    @Digits(integer = 2, fraction = 2, message = "Midterm score must have at most 2 decimal places")
    private BigDecimal midtermScore;

    @DecimalMin(value = "0.0", message = "Final score must be at least 0")
    @DecimalMax(value = "10.0", message = "Final score must not exceed 10")
    @Digits(integer = 2, fraction = 2, message = "Final score must have at most 2 decimal places")
    private BigDecimal finalScore;

    @DecimalMin(value = "0.0", message = "Total score must be at least 0")
    @DecimalMax(value = "10.0", message = "Total score must not exceed 10")
    @Digits(integer = 2, fraction = 2, message = "Total score must have at most 2 decimal places")
    private BigDecimal totalScore;

    @Size(max = 5, message = "Grade must not exceed 5 characters")
    private String grade;
}
