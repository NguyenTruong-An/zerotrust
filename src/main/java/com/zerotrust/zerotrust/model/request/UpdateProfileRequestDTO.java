package com.zerotrust.zerotrust.model.request;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateProfileRequestDTO {
    @Size(max = 100, message = "First name must not exceed 100 characters")
    @Pattern(regexp = ".*\\S.*", message = "First name must not be blank")
    private String firstName;

    @Size(max = 100, message = "Last name must not exceed 100 characters")
    @Pattern(regexp = ".*\\S.*", message = "Last name must not be blank")
    private String lastName;
}
