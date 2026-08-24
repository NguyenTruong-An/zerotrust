package com.zerotrust.zerotrust.model.request;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

import static org.assertj.core.api.Assertions.assertThat;

class UpdateScoreRequestDTOTest {
    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void acceptsPartialScoreUpdate() {
        UpdateScoreRequestDTO request = UpdateScoreRequestDTO.builder()
                .finalScore(new BigDecimal("9.25"))
                .grade("A")
                .build();

        assertThat(validator.validate(request)).isEmpty();
    }

    @Test
    void rejectsInvalidProvidedFields() {
        UpdateScoreRequestDTO request = UpdateScoreRequestDTO.builder()
                .semester((short) 4)
                .academicYear("2025/2026")
                .attendanceScore(new BigDecimal("-0.01"))
                .midtermScore(new BigDecimal("10.001"))
                .finalScore(new BigDecimal("11.00"))
                .totalScore(new BigDecimal("10.001"))
                .grade("PASSED")
                .build();

        assertThat(validator.validate(request))
                .extracting(violation -> violation.getPropertyPath().toString())
                .contains(
                        "semester",
                        "academicYear",
                        "attendanceScore",
                        "midtermScore",
                        "finalScore",
                        "totalScore",
                        "grade");
    }
}
