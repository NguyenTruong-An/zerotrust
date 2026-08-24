package com.zerotrust.zerotrust.model.request;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
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
public class CreateSubjectRequestDTO {
    @NotBlank(message = "Subject code is required")
    @Size(max = 30, message = "Subject code must not exceed 30 characters")
    @Pattern(
            regexp = "^[A-Za-z0-9_-]+$",
            message = "Subject code may only contain letters, numbers, underscores and hyphens")
    private String subjectCode;

    @NotBlank(message = "Subject name is required")
    @Size(max = 200, message = "Subject name must not exceed 200 characters")
    private String subjectName;

    @NotNull(message = "Credits are required")
    @Min(value = 1, message = "Credits must be at least 1")
    @Max(value = 20, message = "Credits must not exceed 20")
    private Short credits;

    @Size(max = 5000, message = "Description must not exceed 5000 characters")
    private String description;
}
