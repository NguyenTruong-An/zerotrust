package com.zerotrust.zerotrust.model.request;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class UpsertSubjectScoresRequestDTOTest {
    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void acceptsValidScoreBatch() {
        UpsertSubjectScoresRequestDTO request = request(List.of(item(
                UUID.randomUUID(), "8.5", "8", "9")));

        assertThat(validator.validate(request)).isEmpty();
    }

    @Test
    void validatesNestedStudentScores() {
        UpsertSubjectScoresRequestDTO request = request(List.of(item(
                null, "-1", "10.001", "11")));

        assertThat(validator.validate(request))
                .extracting(violation -> violation.getPropertyPath().toString())
                .contains(
                        "scores[0].studentId",
                        "scores[0].attendanceScore",
                        "scores[0].midtermScore",
                        "scores[0].finalScore");
    }

    @Test
    void rejectsMissingScoreRowsAndMalformedTerm() {
        UpsertSubjectScoresRequestDTO request = UpsertSubjectScoresRequestDTO.builder()
                .semester((short) 3)
                .academicYear("2026/2027")
                .scores(List.of())
                .build();

        assertThat(validator.validate(request))
                .extracting(violation -> violation.getPropertyPath().toString())
                .contains("semester", "academicYear", "scores");
    }

    private UpsertSubjectScoresRequestDTO request(List<SubjectScoreItemRequestDTO> scores) {
        return UpsertSubjectScoresRequestDTO.builder()
                .semester((short) 1)
                .academicYear("2026-2027")
                .scores(scores)
                .build();
    }

    private SubjectScoreItemRequestDTO item(
            UUID studentId,
            String attendance,
            String midterm,
            String finalScore) {
        return SubjectScoreItemRequestDTO.builder()
                .studentId(studentId)
                .attendanceScore(new BigDecimal(attendance))
                .midtermScore(new BigDecimal(midterm))
                .finalScore(new BigDecimal(finalScore))
                .build();
    }
}
