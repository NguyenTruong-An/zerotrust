package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.converter.UserConverter;
import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
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
    private final UserConverter userConverter;

    @Override
    public UserResponseDTO getCurrentUser(UUID keycloakUserId) {
        return userConverter.convertToDto(findActiveUser(keycloakUserId));
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
