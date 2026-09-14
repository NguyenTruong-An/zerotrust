package com.zerotrust.zerotrust.service.impl;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.math.BigDecimal;

import static org.assertj.core.api.Assertions.assertThat;

class ScoreCalculatorTest {

    @Test
    void calculatesAndRoundsTotalScoreToOneDecimalPlace() {
        ScoreCalculator.Result result = ScoreCalculator.calculate(
                new BigDecimal("8.50"),
                new BigDecimal("8.00"),
                new BigDecimal("9.00"));

        assertThat(result.totalScore()).isEqualByComparingTo("8.7");
        assertThat(result.grade()).isEqualTo("A");
    }

    @Test
    void roundsThreePointNinetyFiveUpBeforeAssigningGrade() {
        ScoreCalculator.Result result = ScoreCalculator.calculate(
                new BigDecimal("3.95"),
                new BigDecimal("3.95"),
                new BigDecimal("3.95"));

        assertThat(result.totalScore()).isEqualByComparingTo("4.0");
        assertThat(result.grade()).isEqualTo("D");
    }

    @ParameterizedTest
    @CsvSource({
            "10.00, A+",
            "9.00, A+",
            "8.95, A+",
            "8.94, A",
            "8.45, A",
            "8.44, B+",
            "7.75, B+",
            "7.74, B",
            "6.95, B",
            "6.94, C+",
            "6.25, C+",
            "6.24, C",
            "5.45, C",
            "5.44, D+",
            "4.75, D+",
            "4.74, D",
            "3.95, D",
            "3.94, F",
            "0.00, F"
    })
    void assignsGradeFromTotalScore(String totalScore, String expectedGrade) {
        assertThat(ScoreCalculator.gradeFor(new BigDecimal(totalScore)))
                .isEqualTo(expectedGrade);
    }
}
