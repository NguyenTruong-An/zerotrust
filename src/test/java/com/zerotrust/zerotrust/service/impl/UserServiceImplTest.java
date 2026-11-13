package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.converter.UserConverter;
import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.identity.IdentityProviderGateway;
import com.zerotrust.zerotrust.model.response.UserResponseDTO;
import com.zerotrust.zerotrust.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
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

    @Mock private com.zerotrust.zerotrust.security.StrictResetOrchestrator strictReset;
    private UserServiceImpl userService;

    @BeforeEach
    void setUp() {
        var now = java.time.Instant.parse("2026-11-13T00:00:00Z");
        var jwt = org.springframework.security.oauth2.jwt.Jwt.withTokenValue("offline-fixture")
                .header("alg", "RS256").subject("11111111-1111-4111-8111-111111111111")
                .claim("azp", "zerotrust-spa").claim("zt_mfa_client", "zerotrust-spa")
                .claim("zt_mfa_subject", "11111111-1111-4111-8111-111111111111")
                .claim("zt_mfa_method", "otp").claim("zt_mfa_at", now.getEpochSecond()).build();
        org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(
                new org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken(jwt,
                        java.util.List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN")), "admin-fixture"));
        userService = new UserServiceImpl(
                userRepository,
                userConverter,
                identityProviderGateway, riskDeviceAdminClient,
                new com.zerotrust.zerotrust.security.FreshAdminMfaGuard(java.time.Clock.fixed(now, java.time.ZoneOffset.UTC),
                        java.time.Duration.ofMinutes(5), "zerotrust-spa"),strictReset);
    }

    @AfterEach void clearAuthentication() {
        org.springframework.security.core.context.SecurityContextHolder.clearContext();
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

        verify(strictReset).reset(any(),org.mockito.ArgumentMatchers.eq(keycloakUserId.toString()));
        org.mockito.Mockito.verifyNoInteractions(identityProviderGateway,riskDeviceAdminClient);
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
    void durableResetFailureIsPropagatedWithoutLegacyMutations() {
        UUID id=activeResetUser();
        org.mockito.Mockito.doThrow(new WebException(ErrorCode.MFA_RESET_PARTIAL)).when(strictReset).reset(any(),any());
        assertThatThrownBy(()->userService.resetMfa(id)).isInstanceOf(WebException.class);
        org.mockito.Mockito.verifyNoInteractions(identityProviderGateway,riskDeviceAdminClient);
    }
    @Test
    void rejectsMissingFreshProofBeforeResolvingTarget() {
        org.springframework.security.core.context.SecurityContextHolder.clearContext();
        assertThatThrownBy(()->userService.resetMfa(UUID.randomUUID())).isInstanceOf(WebException.class);
        org.mockito.Mockito.verifyNoInteractions(userRepository,strictReset,identityProviderGateway,riskDeviceAdminClient);
    }
    private UUID activeResetUser() {
        UUID id=UUID.randomUUID();UserEntity user=new UserEntity();user.setKeycloakUserId(UUID.randomUUID());user.setStatus(UserEntity.Status.ACTIVE);
        when(userRepository.findById(id)).thenReturn(Optional.of(user));return id;
    }
}