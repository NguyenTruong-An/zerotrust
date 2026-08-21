package com.zerotrust.zerotrust.model.request;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class UpdateProfileRequestDTOTest {

    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void rejectsProvidedBlankNames() {
        UpdateProfileRequestDTO request = UpdateProfileRequestDTO.builder()
                .firstName("   ")
                .lastName("")
                .build();

        assertThat(validator.validate(request))
                .extracting(violation -> violation.getPropertyPath().toString())
                .contains("firstName", "lastName");
    }

    @Test
    void acceptsPartialProfileUpdate() {
        UpdateProfileRequestDTO request = UpdateProfileRequestDTO.builder()
                .firstName("Truong An")
                .build();

        assertThat(validator.validate(request)).isEmpty();
    }
}
