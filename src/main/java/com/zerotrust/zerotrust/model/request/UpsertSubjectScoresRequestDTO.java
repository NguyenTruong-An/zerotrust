package com.zerotrust.zerotrust.model.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpsertSubjectScoresRequestDTO {
    @NotNull(message = "Semester is required")
    @Min(value = 1, message = "Semester must be at least 1")
    @Max(value = 2, message = "Semester must not exceed 2")
    private Short semester;

    @NotBlank(message = "Academic year is required")
    @Pattern(
            regexp = "^\\d{4}-\\d{4}$",
            message = "Academic year must use the format YYYY-YYYY")
    private String academicYear;

    @Valid
    @NotEmpty(message = "At least one student score is required")
    @Size(max = 100, message = "A batch must not contain more than 100 student scores")
    private List<SubjectScoreItemRequestDTO> scores;
}
