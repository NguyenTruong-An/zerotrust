package com.zerotrust.risk.config;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

import static org.assertj.core.api.Assertions.assertThat;

class NetworkRiskPropertiesTests {

    private static Validator validator;

    @BeforeAll
    static void createValidator() {
        validator = Validation.buildDefaultValidatorFactory().getValidator();
    }

    @Test
    void acceptsACompleteNetworkPolicy() {
        assertThat(validator.validate(validProperties())).isEmpty();
    }

    @Test
    void rejectsDefaultScoreOutsideTheRiskScale() {
        NetworkRiskProperties properties = validProperties();
        properties.setDefaultScore(new BigDecimal("101"));

        assertThat(validator.validate(properties)).isNotEmpty();
    }

    @Test
    void rejectsElevatedScoreAboveHighScore() {
        NetworkRiskProperties properties = validProperties();
        properties.setElevatedScore(new BigDecimal("80"));
        properties.setHighScore(new BigDecimal("70"));

        assertThat(validator.validate(properties))
                .anyMatch(violation -> violation.getMessage()
                        .contains("elevated score must not exceed high score"));
    }

    @Test
    void rejectsDefaultScoreAboveElevatedScore() {
        NetworkRiskProperties properties = validProperties();
        properties.setDefaultScore(new BigDecimal("60"));

        assertThat(validator.validate(properties))
                .anyMatch(violation -> violation.getMessage()
                        .contains("default score must not exceed elevated score"));
    }

    private NetworkRiskProperties validProperties() {
        NetworkRiskProperties properties = new NetworkRiskProperties();
        properties.setEnabled(true);
        properties.setDefaultScore(new BigDecimal("50"));
        properties.setElevatedScore(new BigDecimal("50"));
        properties.setHighScore(new BigDecimal("100"));
        return properties;
    }
}
