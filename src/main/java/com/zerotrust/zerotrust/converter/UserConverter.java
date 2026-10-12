package com.zerotrust.zerotrust.converter;

import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.model.response.UserResponseDTO;
import org.springframework.stereotype.Component;

@Component
public class UserConverter {
    public UserResponseDTO convertToDto(UserEntity user) {
        return new UserResponseDTO(
                user.getId() == null ? null : user.getId().toString(),
                user.getEmail(),
                user.getUsername(),
                user.getFirstName(),
                user.getLastName(),
                user.getStatus());
    }
}
