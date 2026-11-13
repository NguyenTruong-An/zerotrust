package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.converter.UserConverter;
import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.identity.IdentityProviderGateway;
import com.zerotrust.zerotrust.model.response.UserResponseDTO;
import com.zerotrust.zerotrust.repository.UserRepository;
import com.zerotrust.zerotrust.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final UserConverter userConverter;
    private final IdentityProviderGateway identityProviderGateway;
    private final com.zerotrust.zerotrust.risk.RiskDeviceAdminClient riskDeviceAdminClient;
    private final com.zerotrust.zerotrust.security.FreshAdminMfaGuard freshAdminMfaGuard;
    private final com.zerotrust.zerotrust.security.StrictResetOrchestrator strictReset;

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

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public void resetMfa(UUID userId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        freshAdminMfaGuard.requireFresh(authentication);
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new WebException(ErrorCode.USER_NOT_FOUND));
        if (user.getStatus() != UserEntity.Status.ACTIVE) {
            throw new WebException(ErrorCode.USER_INACTIVE);
        }
        strictReset.reset(authentication,user.getKeycloakUserId().toString());
    }

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public java.util.Map<String,Object> mfaResetChallenge(UUID userId) {
        UserEntity user=userRepository.findById(userId).orElseThrow(()->new WebException(ErrorCode.USER_NOT_FOUND));
        if(user.getStatus()!=UserEntity.Status.ACTIVE)throw new WebException(ErrorCode.USER_INACTIVE);
        return strictReset.challenge(SecurityContextHolder.getContext().getAuthentication(),user.getKeycloakUserId().toString());
    }
}