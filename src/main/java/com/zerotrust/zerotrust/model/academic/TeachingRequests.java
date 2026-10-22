package com.zerotrust.zerotrust.model.academic;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import jakarta.validation.constraints.*;
import java.math.BigDecimal;
import java.time.LocalTime;
import java.util.UUID;

public final class TeachingRequests {
    private TeachingRequests() { }
    public record TeacherCreate(
            @NotBlank @Size(max = 100) String username,
            @NotBlank @Size(min = 8, max = 128) String password,
            @NotBlank @Email @Size(max = 254) String email,
            @NotBlank @Size(max = 100) String firstName,
            @NotBlank @Size(max = 100) String lastName,
            @NotBlank @Size(max = 30) String teacherCode) {
        @Override public String toString() { return "TeacherCreate[redacted]"; }
    }
    public record TeacherUpdate(
            @NotBlank @Email @Size(max = 254) String email,
            @NotBlank @Size(max = 100) String firstName,
            @NotBlank @Size(max = 100) String lastName,
            @NotBlank @Size(max = 30) String teacherCode,
            @NotBlank @Pattern(regexp = "ACTIVE|INACTIVE") String status) { }
    public record Assignment(@NotNull UUID teacherId, @NotNull UUID classId, @NotNull UUID subjectId) { }
    public record Schedule(@NotNull UUID assignmentId, @Min(1) @Max(7) int weekday,
            @NotNull LocalTime startTime, @NotNull LocalTime endTime,
            @NotBlank @Size(max = 80) String room) {
        @AssertTrue(message = "Schedule start must precede end")
        public boolean isChronological() { return startTime == null || endTime == null || startTime.isBefore(endTime); }
    }
    public record Grade(
            @DecimalMin("0") @DecimalMax("10") @Digits(integer = 2, fraction = 2) BigDecimal attendanceScore,
            @DecimalMin("0") @DecimalMax("10") @Digits(integer = 2, fraction = 2) BigDecimal midtermScore,
            @DecimalMin("0") @DecimalMax("10") @Digits(integer = 2, fraction = 2) BigDecimal finalScore,
            @Min(1) @Max(2) Short semester,
            @Pattern(regexp = "^\\d{4}-\\d{4}$") String academicYear) {
        @AssertTrue(message = "At least one grade component is required")
        public boolean isGradePresent() { return attendanceScore != null || midtermScore != null || finalScore != null; }
        @JsonAnySetter
        public void rejectUnknown(String field, Object value) { throw new IllegalArgumentException("Unsupported grade field"); }
    }
}
