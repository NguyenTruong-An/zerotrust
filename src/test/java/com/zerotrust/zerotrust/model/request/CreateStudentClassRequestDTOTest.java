package com.zerotrust.zerotrust.model.request;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CreateStudentClassRequestDTOTest {
    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void acceptsValidStudentClassData() {
        CreateStudentClassRequestDTO request = CreateStudentClassRequestDTO.builder()
                .classCode("AT19B")
                .className("An toan thong tin 19B")
                .department("An toan thong tin")
                .academicYear("2022-2026")
                .build();

        assertThat(validator.validate(request)).isEmpty();
    }

    @Test
    void rejectsMalformedStudentClassData() {
        CreateStudentClassRequestDTO request = CreateStudentClassRequestDTO.builder()
                .classCode("AT 19B")
                .className(" ")
                .department("")
                .academicYear("2022/2026")
                .build();

        assertThat(validator.validate(request))
                .extracting(violation -> violation.getPropertyPath().toString())
                .contains("classCode", "className", "department", "academicYear");
    }
}
