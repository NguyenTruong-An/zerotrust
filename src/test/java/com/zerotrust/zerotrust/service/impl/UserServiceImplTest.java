package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.converter.UserConverter;
import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private UserConverter userConverter;

    private UserServiceImpl userService;

    @BeforeEach
    void setUp() {
        userService = new UserServiceImpl(
                userRepository,
                userConverter);
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

}
