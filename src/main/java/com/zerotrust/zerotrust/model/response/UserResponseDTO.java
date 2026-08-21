package com.zerotrust.zerotrust.model.response;

import com.zerotrust.zerotrust.entity.UserEntity;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserResponseDTO {
    private String id;
    private String email;
    private String username;
    private String firstName;
    private String lastName;
    private UserEntity.Status status;
}
