package com.zerotrust.zerotrust.service;

import com.zerotrust.zerotrust.model.response.UserResponseDTO;

import java.util.List;
import java.util.UUID;

public interface UserService {
    UserResponseDTO getCurrentUser(UUID keycloakUserId);
    List<UserResponseDTO> getAllUsers();
    void resetMfa(UUID userId);
    java.util.Map<String,Object> mfaResetChallenge(UUID userId);
}
