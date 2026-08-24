package com.zerotrust.zerotrust.model.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateStudentClassRequestDTO {
    @NotBlank(message = "Class code is required")
    @Size(max = 30, message = "Class code must not exceed 30 characters")
    @Pattern(
            regexp = "^[A-Za-z0-9_-]+$",
            message = "Class code may only contain letters, numbers, underscores and hyphens")
    private String classCode;

    @NotBlank(message = "Class name is required")
    @Size(max = 100, message = "Class name must not exceed 100 characters")
    private String className;

    @NotBlank(message = "Department is required")
    @Size(max = 150, message = "Department must not exceed 150 characters")
    private String department;

    @NotBlank(message = "Academic year is required")
    @Pattern(
            regexp = "^\\d{4}-\\d{4}$",
            message = "Academic year must use the format YYYY-YYYY")
    private String academicYear;
}
