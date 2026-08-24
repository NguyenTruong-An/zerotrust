package com.zerotrust.zerotrust.identity.keycloak;

import com.zerotrust.zerotrust.config.KeycloakAdminProperties;
import com.zerotrust.zerotrust.identity.model.CreateIdentityUserCommand;
import com.zerotrust.zerotrust.identity.model.IdentityUserProfileSnapshot;
import com.zerotrust.zerotrust.identity.model.ProvisionedIdentityUser;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.CreatedResponseUtil;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Component
@Slf4j
@RequiredArgsConstructor
public class KeycloakUserClient {
    private final Keycloak keycloak;
    private final KeycloakAdminProperties properties;
    private final KeycloakExceptionMapper exceptionMapper;

    public ProvisionedIdentityUser createUser(CreateIdentityUserCommand command) {
        UsersResource users = users();

        try (Response response = users.create(toUserRepresentation(command))) {
            if (response.getStatus() != Response.Status.CREATED.getStatusCode()) {
                throw exceptionMapper.mapCreateFailure(response);
            }
            try {
                String createdId = CreatedResponseUtil.getCreatedId(response);
                return new ProvisionedIdentityUser(UUID.fromString(createdId));
            } catch (RuntimeException ex) {
                deleteUserByUsernameQuietly(users, command.username());
                throw exceptionMapper.invalidResponse();
            }
        } catch (ProcessingException ex) {
            throw exceptionMapper.providerUnavailable();
        } catch (WebApplicationException ex) {
            throw exceptionMapper.mapClientFailure(ex);
        }
    }

    public void deleteUserQuietly(ProvisionedIdentityUser provisionedUser) {
        if (provisionedUser == null) {
            return;
        }

        try {
            users().get(provisionedUser.userId().toString()).remove();
        } catch (RuntimeException cleanupException) {
            log.error(
                    "Failed to roll back Keycloak user {}",
                    provisionedUser.userId(),
                    cleanupException);
        }
    }

    public IdentityUserProfileSnapshot updateUserProfile(
            UUID userId,
            String firstName,
            String lastName,
            String email) {
        try {
            UserResource userResource = users().get(userId.toString());
            UserRepresentation user = userResource.toRepresentation();
            IdentityUserProfileSnapshot previousProfile = new IdentityUserProfileSnapshot(
                    user.getFirstName(),
                    user.getLastName(),
                    user.getEmail(),
                    user.isEmailVerified());
            boolean emailChanged = !emailsEqual(user.getEmail(), email);
            user.setFirstName(firstName);
            user.setLastName(lastName);
            user.setEmail(email);
            if (emailChanged) {
                user.setEmailVerified(false);
            }
            userResource.update(user);
            return previousProfile;
        } catch (ProcessingException ex) {
            throw exceptionMapper.providerUnavailable();
        } catch (WebApplicationException ex) {
            throw exceptionMapper.mapProfileUpdateFailure(ex);
        }
    }

    public void restoreUserProfileQuietly(
            UUID userId,
            IdentityUserProfileSnapshot profile) {
        if (profile == null) {
            return;
        }

        try {
            UserResource userResource = users().get(userId.toString());
            UserRepresentation user = userResource.toRepresentation();
            user.setFirstName(profile.firstName());
            user.setLastName(profile.lastName());
            user.setEmail(profile.email());
            user.setEmailVerified(profile.emailVerified());
            userResource.update(user);
        } catch (RuntimeException cleanupException) {
            log.error("Failed to roll back Keycloak profile for user {}", userId, cleanupException);
        }
    }

    private UsersResource users() {
        return keycloak.realm(properties.realm()).users();
    }

    private UserRepresentation toUserRepresentation(CreateIdentityUserCommand command) {
        CredentialRepresentation password = new CredentialRepresentation();
        password.setType(CredentialRepresentation.PASSWORD);
        password.setValue(command.password());
        password.setTemporary(false);

        UserRepresentation user = new UserRepresentation();
        user.setUsername(command.username());
        user.setEmail(command.email());
        user.setFirstName(command.firstName());
        user.setLastName(command.lastName());
        user.setEnabled(true);
        user.setEmailVerified(false);
        user.setCredentials(List.of(password));
        return user;
    }

    private boolean emailsEqual(String currentEmail, String updatedEmail) {
        if (currentEmail == null || updatedEmail == null) {
            return Objects.equals(currentEmail, updatedEmail);
        }
        return currentEmail.equalsIgnoreCase(updatedEmail);
    }

    private void deleteUserByUsernameQuietly(UsersResource users, String username) {
        try {
            List<UserRepresentation> exactMatches = users
                    .searchByUsername(username, true)
                    .stream()
                    .filter(user -> user.getId() != null)
                    .filter(user -> username.equalsIgnoreCase(user.getUsername()))
                    .toList();

            if (exactMatches.size() == 1) {
                users.get(exactMatches.get(0).getId()).remove();
            } else {
                log.error(
                        "Unable to identify the newly created Keycloak user for rollback: username={}, matches={}",
                        username,
                        exactMatches.size());
            }
        } catch (RuntimeException cleanupException) {
            log.error("Failed to roll back Keycloak user with username {}", username, cleanupException);
        }
    }
}
