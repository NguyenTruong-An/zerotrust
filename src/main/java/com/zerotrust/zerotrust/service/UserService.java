package com.zerotrust.zerotrust.service;

import com.zerotrust.zerotrust.model.response.UserResponseDTO;

import java.util.List;
import java.util.UUID;

public interface UserService {
    UserResponseDTO getCurrentUser(UUID keycloakUserId);
    List<UserResponseDTO> getAllUsers();
}
