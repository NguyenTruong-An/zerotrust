package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.converter.UserConverter;
import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.identity.IdentityProviderGateway;
import com.zerotrust.zerotrust.model.response.UserResponseDTO;
import com.zerotrust.zerotrust.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private UserConverter userConverter;
    @Mock
    private IdentityProviderGateway identityProviderGateway;
    @Mock private com.zerotrust.zerotrust.risk.RiskDeviceAdminClient riskDeviceAdminClient;

    private UserServiceImpl userService;

    @BeforeEach
    void setUp() {
        userService = new UserServiceImpl(
                userRepository,
                userConverter,
                identityProviderGateway, riskDeviceAdminClient);
    }

    @Test
    void returnsCurrentActiveUserByKeycloakId() {
        UUID keycloakUserId = UUID.randomUUID();
        UserEntity entity = new UserEntity();
        entity.setKeycloakUserId(keycloakUserId);
        entity.setStatus(UserEntity.Status.ACTIVE);
        UserResponseDTO response = new UserResponseDTO();

        when(userRepository.findByKeycloakUserId(keycloakUserId))
                .thenReturn(Optional.of(entity));
        when(userConverter.convertToDto(entity)).thenReturn(response);

        assertThat(userService.getCurrentUser(keycloakUserId)).isSameAs(response);
    }

    @Test
    void reportsCurrentUserAsMissingWhenKeycloakIdIsNotLinked() {
        UUID keycloakUserId = UUID.randomUUID();
        when(userRepository.findByKeycloakUserId(keycloakUserId))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.getCurrentUser(keycloakUserId))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.USER_NOT_FOUND);
    }

    @Test
    void rejectsInactiveCurrentUser() {
        UUID keycloakUserId = UUID.randomUUID();
        UserEntity entity = new UserEntity();
        entity.setStatus(UserEntity.Status.INACTIVE);
        when(userRepository.findByKeycloakUserId(keycloakUserId))
                .thenReturn(Optional.of(entity));

        assertThatThrownBy(() -> userService.getCurrentUser(keycloakUserId))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.USER_INACTIVE);
        verify(userConverter, never()).convertToDto(entity);
    }

    @Test
    void resetsMfaForActiveUserUsingLinkedKeycloakId() {
        UUID userId = UUID.randomUUID();
        UUID keycloakUserId = UUID.randomUUID();
        UserEntity entity = new UserEntity();
        entity.setKeycloakUserId(keycloakUserId);
        entity.setStatus(UserEntity.Status.ACTIVE);
        when(userRepository.findById(userId)).thenReturn(Optional.of(entity));

        userService.resetMfa(userId);

        verify(identityProviderGateway).resetMfa(keycloakUserId);
        var order = org.mockito.Mockito.inOrder(riskDeviceAdminClient, identityProviderGateway);
        order.verify(riskDeviceAdminClient).revoke(org.mockito.ArgumentMatchers.eq(keycloakUserId), any(), any());
        order.verify(identityProviderGateway).resetMfa(keycloakUserId);
        order.verify(riskDeviceAdminClient).complete(org.mockito.ArgumentMatchers.eq(keycloakUserId), any(), any());
    }

    @Test
    void rejectsMfaResetForInactiveUser() {
        UUID userId = UUID.randomUUID();
        UserEntity entity = new UserEntity();
        entity.setStatus(UserEntity.Status.INACTIVE);
        when(userRepository.findById(userId)).thenReturn(Optional.of(entity));

        assertThatThrownBy(() -> userService.resetMfa(userId))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.USER_INACTIVE);
        verify(identityProviderGateway, never()).resetMfa(any());
    }

    @Test
    void revocationFailureStopsBeforeTouchingKeycloak() {
        UUID id = activeResetUser();
        org.mockito.Mockito.doThrow(new WebException(ErrorCode.RISK_DEVICE_REVOCATION_FAILED))
                .when(riskDeviceAdminClient).revoke(any(), any(), any());
        assertThatThrownBy(() -> userService.resetMfa(id)).isInstanceOf(WebException.class);
        verify(identityProviderGateway, never()).resetMfa(any());
        verify(riskDeviceAdminClient, never()).complete(any(), any(), any());
    }

    @Test
    void keycloakFailureIsPartialAndDoesNotUnblockRecovery() {
        UUID id = activeResetUser();
        org.mockito.Mockito.doThrow(new WebException(ErrorCode.IDENTITY_PROVIDER_UNAVAILABLE))
                .when(identityProviderGateway).resetMfa(any());
        assertThatThrownBy(() -> userService.resetMfa(id)).isInstanceOf(WebException.class)
                .extracting(ex -> ((WebException) ex).getErrorCode()).isEqualTo(ErrorCode.MFA_RESET_PARTIAL);
        verify(riskDeviceAdminClient, never()).complete(any(), any(), any());
    }

    @Test
    void completionFailureIsReportedInsteadOfSuccess() {
        UUID id = activeResetUser();
        org.mockito.Mockito.doThrow(new WebException(ErrorCode.RISK_DEVICE_REVOCATION_FAILED))
                .when(riskDeviceAdminClient).complete(any(), any(), any());
        assertThatThrownBy(() -> userService.resetMfa(id)).isInstanceOf(WebException.class)
                .extracting(ex -> ((WebException) ex).getErrorCode()).isEqualTo(ErrorCode.MFA_RESET_COMPLETION_PENDING);
    }

    private UUID activeResetUser() {
        UUID id = UUID.randomUUID();
        UserEntity user = new UserEntity();
        user.setKeycloakUserId(UUID.randomUUID());
        user.setStatus(UserEntity.Status.ACTIVE);
        when(userRepository.findById(id)).thenReturn(Optional.of(user));
        return id;
    }

}
