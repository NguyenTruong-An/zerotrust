package com.zerotrust.zerotrust.model.request;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RegisterRequestDTOTest {

    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void rejectsBlankAndMalformedFields() {
        RegisterRequestDTO request = RegisterRequestDTO.builder()
                .username(" ")
                .password("short")
                .firstName(" ")
                .lastName("")
                .email("not-an-email")
                .build();

        var violations = validator.validate(request);

        assertThat(violations)
                .extracting(violation -> violation.getPropertyPath().toString())
                .contains("username", "password", "firstName", "lastName", "email");
    }

    @Test
    void acceptsAValidRegistration() {
        RegisterRequestDTO request = RegisterRequestDTO.builder()
                .username("student01")
                .password("strong-password")
                .firstName("An")
                .lastName("Nguyen")
                .email("an@example.com")
                .build();

        assertThat(validator.validate(request)).isEmpty();
    }
}
