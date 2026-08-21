package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.config.KeycloakAdminProperties;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.request.RegisterRequestDTO;
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
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Service
@Slf4j
@RequiredArgsConstructor
public class KeycloakUserProvisioner {
    private final Keycloak keycloak;
    private final KeycloakAdminProperties properties;

    public ProvisionedUser createUser(RegisterRequestDTO request) {
        UsersResource users = users();

        try (Response response = users.create(toUserRepresentation(request))) {
            if (response.getStatus() != Response.Status.CREATED.getStatusCode()) {
                throw mapCreateFailure(response);
            }

            try {
                String createdId = CreatedResponseUtil.getCreatedId(response);
                return new ProvisionedUser(UUID.fromString(createdId));
            } catch (RuntimeException ex) {
                deleteUserByUsernameQuietly(users, request.getUsername());
                throw new WebException(ErrorCode.IDENTITY_RESPONSE_INVALID);
            }
        } catch (ProcessingException ex) {
            throw new WebException(ErrorCode.IDENTITY_PROVIDER_UNAVAILABLE);
        } catch (WebApplicationException ex) {
            throw mapClientFailure(ex);
        }
    }

    public void deleteUserQuietly(ProvisionedUser provisionedUser) {
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

    public void updateUserProfile(
            UUID userId,
            String firstName,
            String lastName) {
        try {
            UserResource userResource = users().get(userId.toString());
            UserRepresentation user = userResource.toRepresentation();
            user.setFirstName(firstName);
            user.setLastName(lastName);
            userResource.update(user);
        } catch (ProcessingException ex) {
            throw new WebException(ErrorCode.IDENTITY_PROVIDER_UNAVAILABLE);
        } catch (WebApplicationException ex) {
            throw mapClientFailure(ex);
        }
    }

    public void updateUserProfileQuietly(
            UUID userId,
            String firstName,
            String lastName) {
        try {
            updateUserProfile(userId, firstName, lastName);
        } catch (RuntimeException cleanupException) {
            log.error("Failed to roll back Keycloak profile for user {}", userId, cleanupException);
        }
    }

    private UsersResource users() {
        return keycloak.realm(properties.realm()).users();
    }

    private UserRepresentation toUserRepresentation(RegisterRequestDTO request) {
        CredentialRepresentation password = new CredentialRepresentation();
        password.setType(CredentialRepresentation.PASSWORD);
        password.setValue(request.getPassword());
        password.setTemporary(false);

        UserRepresentation user = new UserRepresentation();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEnabled(true);
        user.setEmailVerified(false);
        user.setCredentials(List.of(password));
        return user;
    }

    private WebException mapCreateFailure(Response response) {
        int status = response.getStatus();
        if (status == Response.Status.CONFLICT.getStatusCode()) {
            String responseBody = readResponseBody(response).toLowerCase(Locale.ROOT);
            if (responseBody.contains("email")) {
                return new WebException(ErrorCode.EMAIL_EXISTS);
            }
            if (responseBody.contains("username")) {
                return new WebException(ErrorCode.USERNAME_EXISTS);
            }
            return new WebException(
                    ErrorCode.INVALID_REQUEST,
                    "Username or email already exists");
        }
        if (status == Response.Status.UNAUTHORIZED.getStatusCode()
                || status == Response.Status.FORBIDDEN.getStatusCode()) {
            return new WebException(ErrorCode.IDENTITY_PROVIDER_FORBIDDEN);
        }
        if (status >= 500) {
            return new WebException(ErrorCode.IDENTITY_PROVIDER_UNAVAILABLE);
        }
        return new WebException(ErrorCode.IDENTITY_RESPONSE_INVALID);
    }

    private WebException mapClientFailure(WebApplicationException exception) {
        Response response = exception.getResponse();
        if (response == null) {
            return new WebException(ErrorCode.IDENTITY_RESPONSE_INVALID);
        }

        try (response) {
            int status = response.getStatus();
            if (status == Response.Status.UNAUTHORIZED.getStatusCode()
                    || status == Response.Status.FORBIDDEN.getStatusCode()) {
                return new WebException(ErrorCode.IDENTITY_PROVIDER_FORBIDDEN);
            }
            if (status >= 500) {
                return new WebException(ErrorCode.IDENTITY_PROVIDER_UNAVAILABLE);
            }
            return new WebException(ErrorCode.IDENTITY_RESPONSE_INVALID);
        }
    }

    private String readResponseBody(Response response) {
        try {
            return response.hasEntity() ? response.readEntity(String.class) : "";
        } catch (RuntimeException ignored) {
            return "";
        }
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

    public record ProvisionedUser(UUID userId) {
    }
}
