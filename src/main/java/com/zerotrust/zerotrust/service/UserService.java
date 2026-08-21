package com.zerotrust.zerotrust.service;

import com.zerotrust.zerotrust.model.request.RegisterRequestDTO;
import com.zerotrust.zerotrust.model.request.UpdateProfileRequestDTO;
import com.zerotrust.zerotrust.model.response.UserResponseDTO;

import java.util.List;
import java.util.UUID;

public interface UserService {
    UserResponseDTO register(RegisterRequestDTO registerRequestDTO);
    UserResponseDTO getCurrentUser(UUID keycloakUserId);
    UserResponseDTO updateCurrentUser(UUID keycloakUserId, UpdateProfileRequestDTO request);
    List<UserResponseDTO> getAllUsers();
}
