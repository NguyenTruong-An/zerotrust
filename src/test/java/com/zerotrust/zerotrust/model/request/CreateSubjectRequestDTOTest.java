package com.zerotrust.zerotrust.model.request;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CreateSubjectRequestDTOTest {
    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void acceptsValidSubjectData() {
        CreateSubjectRequestDTO request = CreateSubjectRequestDTO.builder()
                .subjectCode("SEC101")
                .subjectName("Nhap mon an toan thong tin")
                .credits((short) 3)
                .description("Kien thuc co ban ve an toan thong tin")
                .build();

        assertThat(validator.validate(request)).isEmpty();
    }

    @Test
    void rejectsMalformedSubjectData() {
        CreateSubjectRequestDTO request = CreateSubjectRequestDTO.builder()
                .subjectCode("SEC 101")
                .subjectName(" ")
                .credits((short) 0)
                .description("a".repeat(5001))
                .build();

        assertThat(validator.validate(request))
                .extracting(violation -> violation.getPropertyPath().toString())
                .contains("subjectCode", "subjectName", "credits", "description");
    }
}
