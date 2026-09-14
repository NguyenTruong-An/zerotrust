package com.zerotrust.zerotrust.model.request;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Digits;
import jakarta.validation.constraints.NotNull;
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
public class SubjectScoreItemRequestDTO {
    @NotNull(message = "Student ID is required")
    private UUID studentId;

    @NotNull(message = "Attendance score is required")
    @DecimalMin(value = "0.0", message = "Attendance score must be at least 0")
    @DecimalMax(value = "10.0", message = "Attendance score must not exceed 10")
    @Digits(integer = 2, fraction = 2, message = "Attendance score must have at most 2 decimal places")
    private BigDecimal attendanceScore;

    @NotNull(message = "Midterm score is required")
    @DecimalMin(value = "0.0", message = "Midterm score must be at least 0")
    @DecimalMax(value = "10.0", message = "Midterm score must not exceed 10")
    @Digits(integer = 2, fraction = 2, message = "Midterm score must have at most 2 decimal places")
    private BigDecimal midtermScore;

    @NotNull(message = "Final score is required")
    @DecimalMin(value = "0.0", message = "Final score must be at least 0")
    @DecimalMax(value = "10.0", message = "Final score must not exceed 10")
    @Digits(integer = 2, fraction = 2, message = "Final score must have at most 2 decimal places")
    private BigDecimal finalScore;
}
