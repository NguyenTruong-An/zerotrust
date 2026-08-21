package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.converter.UserConverter;
import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.request.RegisterRequestDTO;
import com.zerotrust.zerotrust.model.request.UpdateProfileRequestDTO;
import com.zerotrust.zerotrust.model.response.UserResponseDTO;
import com.zerotrust.zerotrust.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;

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
    void returnsSavedUserAfterRegistration() {
        RegisterRequestDTO request = validRequest();
        UUID keycloakUserId = UUID.randomUUID();
        KeycloakUserProvisioner.ProvisionedUser provisionedUser = provisionedUser(keycloakUserId);
        UserEntity entity = new UserEntity();
        UserResponseDTO response = new UserResponseDTO();

        when(userConverter.convertToEntity(request)).thenReturn(entity);
        when(keycloakUserProvisioner.createUser(request)).thenReturn(provisionedUser);
        when(userRepository.saveAndFlush(entity)).thenReturn(entity);
        when(userConverter.convertToDto(entity)).thenReturn(response);

        assertThat(userService.register(request)).isSameAs(response);
        assertThat(entity.getKeycloakUserId()).isEqualTo(keycloakUserId);
        verify(keycloakUserProvisioner, never()).deleteUserQuietly(provisionedUser);
    }

    @Test
    void deletesKeycloakUserWhenDatabaseSaveFails() {
        RegisterRequestDTO request = validRequest();
        UUID keycloakUserId = UUID.randomUUID();
        KeycloakUserProvisioner.ProvisionedUser provisionedUser = provisionedUser(keycloakUserId);
        UserEntity entity = new UserEntity();
        DataIntegrityViolationException databaseException =
                new DataIntegrityViolationException("unknown constraint");

        when(userConverter.convertToEntity(request)).thenReturn(entity);
        when(keycloakUserProvisioner.createUser(request)).thenReturn(provisionedUser);
        when(userRepository.saveAndFlush(entity)).thenThrow(databaseException);

        assertThatThrownBy(() -> userService.register(request))
                .isSameAs(databaseException);
        verify(keycloakUserProvisioner).deleteUserQuietly(provisionedUser);
    }

    @Test
    void reportsUsernameConflictWhenConcurrentInsertWins() {
        RegisterRequestDTO request = validRequest();
        UUID keycloakUserId = UUID.randomUUID();
        KeycloakUserProvisioner.ProvisionedUser provisionedUser = provisionedUser(keycloakUserId);
        UserEntity entity = new UserEntity();

        when(userRepository.existsByUsernameIgnoreCase(request.getUsername()))
                .thenReturn(false, true);
        when(userConverter.convertToEntity(request)).thenReturn(entity);
        when(keycloakUserProvisioner.createUser(request)).thenReturn(provisionedUser);
        when(userRepository.saveAndFlush(entity))
                .thenThrow(new DataIntegrityViolationException("duplicate username"));

        assertThatThrownBy(() -> userService.register(request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.USERNAME_EXISTS);
        verify(keycloakUserProvisioner).deleteUserQuietly(provisionedUser);
    }

    @Test
    void keepsKeycloakUserWhenResponseMappingFailsAfterDatabaseSave() {
        RegisterRequestDTO request = validRequest();
        UUID keycloakUserId = UUID.randomUUID();
        KeycloakUserProvisioner.ProvisionedUser provisionedUser = provisionedUser(keycloakUserId);
        UserEntity entity = new UserEntity();
        RuntimeException mappingException = new RuntimeException("response mapping failed");

        when(userConverter.convertToEntity(request)).thenReturn(entity);
        when(keycloakUserProvisioner.createUser(request)).thenReturn(provisionedUser);
        when(userRepository.saveAndFlush(entity)).thenReturn(entity);
        when(userConverter.convertToDto(entity)).thenThrow(mappingException);

        assertThatThrownBy(() -> userService.register(request))
                .isSameAs(mappingException);
        verify(keycloakUserProvisioner, never()).deleteUserQuietly(provisionedUser);
    }

    @Test
    void rejectsExistingUsernameBeforeCallingKeycloak() {
        RegisterRequestDTO request = validRequest();
        when(userRepository.existsByUsernameIgnoreCase(request.getUsername())).thenReturn(true);

        assertThatThrownBy(() -> userService.register(request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.USERNAME_EXISTS);
        verify(keycloakUserProvisioner, never()).createUser(request);
    }

    @Test
    void doesNotCreateKeycloakUserWhenEntityMappingFails() {
        RegisterRequestDTO request = validRequest();
        RuntimeException mappingException = new RuntimeException("entity mapping failed");
        when(userConverter.convertToEntity(request)).thenThrow(mappingException);

        assertThatThrownBy(() -> userService.register(request))
                .isSameAs(mappingException);
        verify(keycloakUserProvisioner, never()).createUser(request);
    }

    @Test
    void doesNotCreateKeycloakUserWhenEntityConverterReturnsNull() {
        RegisterRequestDTO request = validRequest();
        when(userConverter.convertToEntity(request)).thenReturn(null);

        assertThatThrownBy(() -> userService.register(request))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("User converter returned null");
        verify(keycloakUserProvisioner, never()).createUser(request);
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

    private KeycloakUserProvisioner.ProvisionedUser provisionedUser(UUID userId) {
        return new KeycloakUserProvisioner.ProvisionedUser(userId);
    }

    private RegisterRequestDTO validRequest() {
        return RegisterRequestDTO.builder()
                .username("student01")
                .password("strong-password")
                .firstName("An")
                .lastName("Nguyen")
                .email("an@example.com")
                .build();
    }
}
