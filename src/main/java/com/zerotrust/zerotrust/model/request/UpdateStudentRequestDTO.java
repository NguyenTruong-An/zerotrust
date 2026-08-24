package com.zerotrust.zerotrust.model.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Past;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateStudentRequestDTO {
    @Email(message = "Email is invalid")
    @Size(max = 254, message = "Email must not exceed 254 characters")
    @Pattern(regexp = ".*\\S.*", message = "Email must not be blank")
    private String email;

    @Size(max = 100, message = "First name must not exceed 100 characters")
    @Pattern(regexp = ".*\\S.*", message = "First name must not be blank")
    private String firstName;

    @Size(max = 100, message = "Last name must not exceed 100 characters")
    @Pattern(regexp = ".*\\S.*", message = "Last name must not be blank")
    private String lastName;

    @Size(max = 30, message = "Student code must not exceed 30 characters")
    @Pattern(regexp = ".*\\S.*", message = "Student code must not be blank")
    private String studentCode;

    @Past(message = "Date of birth must be in the past")
    private LocalDate dateOfBirth;

    @Pattern(
            regexp = "(?i)MALE|FEMALE|OTHER",
            message = "Gender must be MALE, FEMALE or OTHER")
    private String gender;

    @Size(max = 20, message = "Phone must not exceed 20 characters")
    @Pattern(
            regexp = "^[0-9+(). -]*$",
            message = "Phone contains invalid characters")
    private String phone;

    @Size(max = 500, message = "Address must not exceed 500 characters")
    private String address;

    @Size(max = 30, message = "Student class code must not exceed 30 characters")
    @Pattern(
            regexp = "^[A-Za-z0-9_-]+$",
            message = "Student class code may only contain letters, numbers, underscores and hyphens")
    private String classCode;
}
