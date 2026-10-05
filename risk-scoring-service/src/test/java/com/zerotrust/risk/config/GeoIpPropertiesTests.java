package com.zerotrust.risk.config;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class GeoIpPropertiesTests {

    private static Validator validator;

    @BeforeAll
    static void createValidator() {
        validator = Validation.buildDefaultValidatorFactory().getValidator();
    }

    @Test
    void allowsGeoIpToRemainDisabledWithoutACommercialDatabaseFile() {
        assertThat(validator.validate(new GeoIpProperties())).isEmpty();
    }

    @Test
    void requiresCityDatabasePathWhenGeoIpIsEnabled() {
        GeoIpProperties properties = new GeoIpProperties();
        properties.setEnabled(true);

        assertThat(validator.validate(properties))
                .anyMatch(violation -> violation.getMessage()
                        .contains("city database path is required"));
    }
}
