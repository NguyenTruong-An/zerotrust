package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.converter.UserConverter;
import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.request.UpdateProfileRequestDTO;
import com.zerotrust.zerotrust.model.response.UserResponseDTO;
import com.zerotrust.zerotrust.repository.UserRepository;
import com.zerotrust.zerotrust.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final KeycloakUserProvisioner keycloakUserProvisioner;
    private final UserConverter userConverter;

    @Override
    public UserResponseDTO getCurrentUser(UUID keycloakUserId) {
        return userConverter.convertToDto(findActiveUser(keycloakUserId));
    }

    @Override
    public UserResponseDTO updateCurrentUser(
            UUID keycloakUserId,
            UpdateProfileRequestDTO request) {
        if (request.getFirstName() == null && request.getLastName() == null) {
            throw new WebException(
                    ErrorCode.INVALID_REQUEST,
                    "At least one profile field must be provided");
        }

        UserEntity user = findActiveUser(keycloakUserId);
        String previousFirstName = user.getFirstName();
        String previousLastName = user.getLastName();
        String updatedFirstName = request.getFirstName() == null
                ? previousFirstName
                : request.getFirstName().trim();
        String updatedLastName = request.getLastName() == null
                ? previousLastName
                : request.getLastName().trim();

        keycloakUserProvisioner.updateUserProfile(
                keycloakUserId,
                updatedFirstName,
                updatedLastName);

        user.setFirstName(updatedFirstName);
        user.setLastName(updatedLastName);

        UserEntity savedUser;
        try {
            savedUser = userRepository.saveAndFlush(user);
        } catch (RuntimeException ex) {
            keycloakUserProvisioner.updateUserProfileQuietly(
                    keycloakUserId,
                    previousFirstName,
                    previousLastName);
            throw ex;
        }

        return userConverter.convertToDto(savedUser);
    }

    private UserEntity findActiveUser(UUID keycloakUserId) {
        UserEntity user = userRepository.findByKeycloakUserId(keycloakUserId)
                .orElseThrow(() -> new WebException(ErrorCode.USER_NOT_FOUND));

        if (user.getStatus() != UserEntity.Status.ACTIVE) {
            throw new WebException(ErrorCode.USER_INACTIVE);
        }

        return user;
    }

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public List<UserResponseDTO> getAllUsers() {
        return userRepository.findAll().stream()
                .map(userConverter::convertToDto)
                .toList();
    }

}
