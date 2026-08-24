package com.zerotrust.zerotrust.model.request;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;

class CreateStudentRequestDTOTest {
    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void acceptsValidStudentAccountData() {
        assertThat(validator.validate(validRequest())).isEmpty();
    }

    @Test
    void rejectsInvalidAccountAndStudentData() {
        CreateStudentRequestDTO request = CreateStudentRequestDTO.builder()
                .username("invalid username")
                .password("short")
                .email("invalid-email")
                .firstName(" ")
                .lastName("")
                .studentCode(" ")
                .dateOfBirth(LocalDate.now().plusDays(1))
                .gender("UNKNOWN")
                .phone("not-a-phone")
                .build();

        assertThat(validator.validate(request))
                .extracting(violation -> violation.getPropertyPath().toString())
                .contains(
                        "username",
                        "password",
                        "email",
                        "firstName",
                        "lastName",
                        "studentCode",
                        "dateOfBirth",
                        "gender",
                        "phone",
                        "classCode");
    }

    private CreateStudentRequestDTO validRequest() {
        return CreateStudentRequestDTO.builder()
                .username("student01")
                .password("Temp@123456")
                .email("student01@example.com")
                .firstName("An")
                .lastName("Nguyen")
                .studentCode("SV001")
                .dateOfBirth(LocalDate.of(2003, 5, 20))
                .gender("MALE")
                .phone("0987654321")
                .address("Ha Noi")
                .classCode("AT19B")
                .build();
    }
}
