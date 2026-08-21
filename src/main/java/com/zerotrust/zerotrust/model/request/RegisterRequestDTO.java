package com.zerotrust.zerotrust.model.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class RegisterRequestDTO {
        @NotBlank(message = "Username is required")
        @Size(min = 4, max = 50, message = "Username must contain between 4 and 50 characters")
        String username;
        @NotBlank(message = "Password is required")
        @Size(min = 8, max = 100, message = "Password must contain between 8 and 100 characters")
        String password;
        @NotBlank(message = "First name is required")
        @Size(max = 100, message = "First name must not exceed 100 characters")
        String firstName;
        @NotBlank(message = "Last name is required")
        @Size(max = 100, message = "Last name must not exceed 100 characters")
        String lastName;
        @NotBlank(message = "Email is required")
        @Email(message = "Email is invalid")
        @Size(max = 255, message = "Email must not exceed 255 characters")
        String email;
}
