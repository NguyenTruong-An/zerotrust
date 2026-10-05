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
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new WebException(ErrorCode.USER_NOT_FOUND));
        if (user.getStatus() != UserEntity.Status.ACTIVE) {
            throw new WebException(ErrorCode.USER_INACTIVE);
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String requestedBy = authentication == null ? "system" : authentication.getName();
        UUID operationId = UUID.randomUUID();
        riskDeviceAdminClient.revoke(user.getKeycloakUserId(), operationId, requestedBy);
        try {
            identityProviderGateway.resetMfa(user.getKeycloakUserId());
        } catch (RuntimeException exception) {
            log.warn("MFA reset incomplete: operationId={}, stage=KEYCLOAK_RESET", operationId);
            throw new WebException(ErrorCode.MFA_RESET_PARTIAL);
        }
        try {
            riskDeviceAdminClient.complete(user.getKeycloakUserId(), operationId, requestedBy);
        } catch (RuntimeException exception) {
            log.warn("MFA reset incomplete: operationId={}, stage=REVOCATION_COMPLETION", operationId);
            throw new WebException(ErrorCode.MFA_RESET_COMPLETION_PENDING);
        }
        log.info(
                "MFA reset completed: portalUserId={}, keycloakUserId={}, requestedBy={}, operationId={}",
                userId,
                user.getKeycloakUserId(),
                requestedBy, operationId);
    }

}
