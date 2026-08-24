package com.zerotrust.zerotrust.model.response;

import com.zerotrust.zerotrust.entity.UserEntity;

import java.time.LocalDate;
import java.util.UUID;

public record StudentResponseDTO(
        UUID id,
        UUID userId,
        String username,
        String email,
        String firstName,
        String lastName,
        UserEntity.Status status,
        String studentCode,
        LocalDate dateOfBirth,
        String gender,
        String phone,
        String address,
        String classCode,
        String className
) {
}
