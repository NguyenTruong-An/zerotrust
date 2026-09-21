package com.zerotrust.risk.config;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.Duration;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

class TemporalRiskPropertiesTests {

    private static Validator validator;

    @BeforeAll
    static void createValidator() {
        validator = Validation.buildDefaultValidatorFactory().getValidator();
    }

    @Test
    void acceptsACompleteTemporalPolicy() {
        assertThat(validator.validate(validProperties())).isEmpty();
    }

    @Test
    void rejectsNonPositiveHistoryWindow() {
        TemporalRiskProperties properties = validProperties();
        properties.setHistoryWindow(Duration.ZERO);

        assertThat(validator.validate(properties))
                .anyMatch(violation -> violation.getMessage()
                        .contains("history window must be positive"));
    }

    @Test
    void rejectsMinimumEventsAboveMaximumEvents() {
        TemporalRiskProperties properties = validProperties();
        properties.setMinimumEvents(11);
        properties.setMaximumEvents(10);

        assertThat(validator.validate(properties))
                .anyMatch(violation -> violation.getMessage()
                        .contains("minimum events must not exceed maximum events"));
    }

    @Test
    void rejectsMediumScoreAboveHighScore() {
        TemporalRiskProperties properties = validProperties();
        properties.setMediumScore(new BigDecimal("80"));
        properties.setHighScore(new BigDecimal("70"));

        assertThat(validator.validate(properties))
                .anyMatch(violation -> violation.getMessage()
                        .contains("medium score must not exceed high score"));
    }

    private TemporalRiskProperties validProperties() {
        TemporalRiskProperties properties = new TemporalRiskProperties();
        properties.setHistoryWindow(Duration.ofDays(90));
        properties.setMinimumEvents(5);
        properties.setMaximumEvents(200);
        properties.setZoneId(ZoneOffset.UTC);
        properties.setHourTolerance(1);
        properties.setMinimumDayFrequency(new BigDecimal("0.10"));
        properties.setMinimumHourFrequency(new BigDecimal("0.20"));
        properties.setMediumScore(new BigDecimal("50"));
        properties.setHighScore(new BigDecimal("100"));
        return properties;
    }
}
