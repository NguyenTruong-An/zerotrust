package com.zerotrust.zerotrust.model.request;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;

class UpdateStudentRequestDTOTest {
    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void acceptsPartialStudentUpdate() {
        UpdateStudentRequestDTO request = UpdateStudentRequestDTO.builder()
                .email("student@example.com")
                .phone("0987654321")
                .classCode("AT19C")
                .build();

        assertThat(validator.validate(request)).isEmpty();
    }

    @Test
    void rejectsInvalidProvidedFields() {
        UpdateStudentRequestDTO request = UpdateStudentRequestDTO.builder()
                .email("not-an-email")
                .firstName("   ")
                .studentCode("")
                .dateOfBirth(LocalDate.now().plusDays(1))
                .gender("UNKNOWN")
                .phone("phone-number")
                .classCode("AT 19C")
                .build();

        assertThat(validator.validate(request))
                .extracting(violation -> violation.getPropertyPath().toString())
                .contains(
                        "email",
                        "firstName",
                        "studentCode",
                        "dateOfBirth",
                        "gender",
                        "phone",
                        "classCode");
    }
}
