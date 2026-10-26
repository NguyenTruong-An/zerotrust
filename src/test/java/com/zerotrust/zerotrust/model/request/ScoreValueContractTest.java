package com.zerotrust.zerotrust.model.request;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ScoreValueContractTest {
    private static final Map<String, String> COMPONENTS = Map.of(
            "attendanceScore", "Attendance score",
            "midtermScore", "Midterm score",
            "finalScore", "Final score");
    private static ValidatorFactory factory;
    private static Validator validator;

    @BeforeAll
    static void setUp() {
        factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @AfterAll
    static void tearDown() {
        factory.close();
    }

    @ParameterizedTest
    @CsvSource({"-0.01,must be at least 0", "10.01,must not exceed 10",
            "1.001,must have at most 2 decimal places"})
    void preservesComponentMessagesAcrossAllScoreRequests(String value, String message) {
        for (Object request : requests(new BigDecimal(value))) {
            COMPONENTS.forEach((field, label) -> assertThat(validator.validateProperty(request, field))
                    .extracting(violation -> violation.getMessage())
                    .containsExactly(label + " " + message));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "0.00", "9.99", "10.00"})
    void acceptsBoundaryValuesAcrossAllScoreRequests(String value) {
        for (Object request : requests(new BigDecimal(value))) {
            COMPONENTS.keySet().forEach(field ->
                    assertThat(validator.validateProperty(request, field)).isEmpty());
        }
    }

    private List<Object> requests(BigDecimal score) {
        return List.of(
                CreateScoreRequestDTO.builder()
                        .attendanceScore(score).midtermScore(score).finalScore(score).build(),
                UpdateScoreRequestDTO.builder()
                        .attendanceScore(score).midtermScore(score).finalScore(score).build());
    }
}
