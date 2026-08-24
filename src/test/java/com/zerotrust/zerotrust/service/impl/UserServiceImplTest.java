package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.converter.UserConverter;
import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.request.UpdateProfileRequestDTO;
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
    private KeycloakUserProvisioner keycloakUserProvisioner;
    @Mock
    private UserConverter userConverter;

    private UserServiceImpl userService;

    @BeforeEach
    void setUp() {
        userService = new UserServiceImpl(
                userRepository,
                keycloakUserProvisioner,
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

    @Test
    void updatesCurrentUserProfileInKeycloakAndDatabase() {
        UUID keycloakUserId = UUID.randomUUID();
        UserEntity entity = activeUser("An", "Nguyen");
        UpdateProfileRequestDTO request = UpdateProfileRequestDTO.builder()
                .firstName("  Truong An  ")
                .build();
        UserResponseDTO response = new UserResponseDTO();

        when(userRepository.findByKeycloakUserId(keycloakUserId))
                .thenReturn(Optional.of(entity));
        when(userRepository.saveAndFlush(entity)).thenReturn(entity);
        when(userConverter.convertToDto(entity)).thenReturn(response);

        assertThat(userService.updateCurrentUser(keycloakUserId, request)).isSameAs(response);
        assertThat(entity.getFirstName()).isEqualTo("Truong An");
        assertThat(entity.getLastName()).isEqualTo("Nguyen");
        verify(keycloakUserProvisioner)
                .updateUserProfile(keycloakUserId, "Truong An", "Nguyen");
        verify(keycloakUserProvisioner, never())
                .updateUserProfileQuietly(keycloakUserId, "An", "Nguyen");
    }

    @Test
    void rejectsProfileUpdateWithoutAnyFields() {
        UUID keycloakUserId = UUID.randomUUID();
        UpdateProfileRequestDTO request = new UpdateProfileRequestDTO();

        assertThatThrownBy(() -> userService.updateCurrentUser(keycloakUserId, request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REQUEST);
        verify(keycloakUserProvisioner, never())
                .updateUserProfile(keycloakUserId, null, null);
    }

    @Test
    void restoresKeycloakProfileWhenDatabaseUpdateFails() {
        UUID keycloakUserId = UUID.randomUUID();
        UserEntity entity = activeUser("An", "Nguyen");
        UpdateProfileRequestDTO request = UpdateProfileRequestDTO.builder()
                .lastName("Tran")
                .build();
        RuntimeException databaseException = new RuntimeException("database unavailable");

        when(userRepository.findByKeycloakUserId(keycloakUserId))
                .thenReturn(Optional.of(entity));
        when(userRepository.saveAndFlush(entity)).thenThrow(databaseException);

        assertThatThrownBy(() -> userService.updateCurrentUser(keycloakUserId, request))
                .isSameAs(databaseException);
        verify(keycloakUserProvisioner)
                .updateUserProfile(keycloakUserId, "An", "Tran");
        verify(keycloakUserProvisioner)
                .updateUserProfileQuietly(keycloakUserId, "An", "Nguyen");
    }

    @Test
    void keepsUpdatedProfileWhenResponseMappingFailsAfterDatabaseUpdate() {
        UUID keycloakUserId = UUID.randomUUID();
        UserEntity entity = activeUser("An", "Nguyen");
        UpdateProfileRequestDTO request = UpdateProfileRequestDTO.builder()
                .firstName("Binh")
                .build();
        RuntimeException mappingException = new RuntimeException("response mapping failed");

        when(userRepository.findByKeycloakUserId(keycloakUserId))
                .thenReturn(Optional.of(entity));
        when(userRepository.saveAndFlush(entity)).thenReturn(entity);
        when(userConverter.convertToDto(entity)).thenThrow(mappingException);

        assertThatThrownBy(() -> userService.updateCurrentUser(keycloakUserId, request))
                .isSameAs(mappingException);
        verify(keycloakUserProvisioner, never())
                .updateUserProfileQuietly(keycloakUserId, "An", "Nguyen");
    }

    private UserEntity activeUser(String firstName, String lastName) {
        UserEntity entity = new UserEntity();
        entity.setFirstName(firstName);
        entity.setLastName(lastName);
        entity.setStatus(UserEntity.Status.ACTIVE);
        return entity;
    }

}
