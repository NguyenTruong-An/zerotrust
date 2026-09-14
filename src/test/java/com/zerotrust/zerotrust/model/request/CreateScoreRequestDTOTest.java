package com.zerotrust.zerotrust.model.request;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class CreateScoreRequestDTOTest {
    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void acceptsThreeRequiredScoreComponents() {
        CreateScoreRequestDTO request = CreateScoreRequestDTO.builder()
                .subjectId(UUID.randomUUID())
                .semester((short) 1)
                .academicYear("2025-2026")
                .attendanceScore(new BigDecimal("8.50"))
                .midtermScore(new BigDecimal("8.00"))
                .finalScore(new BigDecimal("9.00"))
                .build();

        assertThat(validator.validate(request)).isEmpty();
    }

    @Test
    void rejectsMalformedScoreData() {
        CreateScoreRequestDTO request = CreateScoreRequestDTO.builder()
                .semester((short) 3)
                .academicYear("2025/2026")
                .attendanceScore(new BigDecimal("-0.01"))
                .midtermScore(new BigDecimal("10.001"))
                .finalScore(new BigDecimal("11.00"))
                .build();

        assertThat(validator.validate(request))
                .extracting(violation -> violation.getPropertyPath().toString())
                .contains(
                        "subjectId",
                        "semester",
                        "academicYear",
                        "attendanceScore",
                        "midtermScore",
                        "finalScore");
    }

    @Test
    void requiresAllThreeScoreComponents() {
        CreateScoreRequestDTO request = CreateScoreRequestDTO.builder()
                .subjectId(UUID.randomUUID())
                .semester((short) 1)
                .academicYear("2025-2026")
                .build();

        assertThat(validator.validate(request))
                .extracting(violation -> violation.getPropertyPath().toString())
                .contains("attendanceScore", "midtermScore", "finalScore");
    }
}
