package com.zerotrust.zerotrust.identity.keycloak;

import com.zerotrust.zerotrust.config.KeycloakAdminProperties;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.identity.model.CreateIdentityUserCommand;
import com.zerotrust.zerotrust.identity.model.IdentityUserProfileSnapshot;
import com.zerotrust.zerotrust.identity.model.ProvisionedIdentityUser;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.UserRepresentation;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KeycloakUserClientTest {
    @Mock
    private Keycloak keycloak;
    @Mock
    private RealmResource realmResource;
    @Mock
    private UsersResource usersResource;
    @Mock
    private UserResource userResource;
    @Mock
    private Response response;
    @Captor
    private ArgumentCaptor<UserRepresentation> userCaptor;

    private KeycloakUserClient client;

    @BeforeEach
    void setUp() {
        KeycloakAdminProperties properties = new KeycloakAdminProperties(
                "http://localhost:8180",
                "DoAn",
                "test-client",
                "test-secret",
                Duration.ofSeconds(1),
                Duration.ofSeconds(1),
                2,
                10);
        client = new KeycloakUserClient(
                keycloak,
                properties,
                new KeycloakExceptionMapper());
    }

    @Test
    void createsUserAndReturnsCreatedId() {
        stubUsersResource();
        CreateIdentityUserCommand request = validRequest();
        UUID userId = UUID.randomUUID();
        when(response.getStatus()).thenReturn(Response.Status.CREATED.getStatusCode());
        when(response.getStatusInfo()).thenReturn(Response.Status.CREATED);
        when(response.getLocation()).thenReturn(
                URI.create("http://localhost/admin/realms/DoAn/users/" + userId));
        when(usersResource.create(any())).thenReturn(response);

        assertThat(client.createUser(request).userId()).isEqualTo(userId);

        verify(usersResource).create(userCaptor.capture());
        UserRepresentation createdUser = userCaptor.getValue();
        assertThat(createdUser.getUsername()).isEqualTo(request.username());
        assertThat(createdUser.getEmail()).isEqualTo(request.email());
        assertThat(createdUser.getCredentials()).singleElement()
                .satisfies(credential -> {
                    assertThat(credential.getValue()).isEqualTo(request.password());
                    assertThat(credential.isTemporary()).isFalse();
                });
        verify(response).close();
    }

    @Test
    void deletesCreatedUserByUsernameWhenLocationHeaderIsMissing() {
        stubUsersResource();
        CreateIdentityUserCommand request = validRequest();
        UUID userId = UUID.randomUUID();
        UserRepresentation createdUser = new UserRepresentation();
        createdUser.setId(userId.toString());
        createdUser.setUsername(request.username());

        when(response.getStatus()).thenReturn(Response.Status.CREATED.getStatusCode());
        when(response.getStatusInfo()).thenReturn(Response.Status.CREATED);
        when(response.getLocation()).thenReturn(null);
        when(usersResource.create(any())).thenReturn(response);
        when(usersResource.searchByUsername(request.username(), true))
                .thenReturn(List.of(createdUser));
        when(usersResource.get(userId.toString())).thenReturn(userResource);

        assertThatThrownBy(() -> client.createUser(request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.IDENTITY_RESPONSE_INVALID);
        verify(userResource).remove();
    }

    @Test
    void mapsEmailConflictFromCreateUser() {
        stubUsersResource();
        when(response.getStatus()).thenReturn(Response.Status.CONFLICT.getStatusCode());
        when(response.hasEntity()).thenReturn(true);
        when(response.readEntity(String.class)).thenReturn("User exists with same email");
        when(usersResource.create(any())).thenReturn(response);

        assertThatThrownBy(() -> client.createUser(validRequest()))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.EMAIL_EXISTS);
    }

    @Test
    void reportsKeycloakAsUnavailableWhenCreateCannotBeSent() {
        stubUsersResource();
        when(usersResource.create(any()))
                .thenThrow(new ProcessingException("connection refused"));

        assertThatThrownBy(() -> client.createUser(validRequest()))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.IDENTITY_PROVIDER_UNAVAILABLE);
    }

    @Test
    void reportsInvalidServiceAccountCredentials() {
        stubUsersResource();
        when(response.getStatus()).thenReturn(Response.Status.UNAUTHORIZED.getStatusCode());
        when(response.getStatusInfo()).thenReturn(Response.Status.UNAUTHORIZED);
        WebApplicationException unauthorized = new WebApplicationException(response);
        when(usersResource.create(any())).thenThrow(unauthorized);

        assertThatThrownBy(() -> client.createUser(validRequest()))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.IDENTITY_PROVIDER_FORBIDDEN);
        verify(response).close();
    }

    @Test
    void deletesProvisionedUserById() {
        stubUsersResource();
        UUID userId = UUID.randomUUID();
        when(usersResource.get(userId.toString())).thenReturn(userResource);

        client.deleteUserQuietly(new ProvisionedIdentityUser(userId));

        verify(userResource).remove();
    }

    @Test
    void ignoresNullProvisionedUserDuringRollback() {
        client.deleteUserQuietly(null);

        verify(usersResource, never()).get(any());
    }

    @Test
    void updatesKeycloakUserProfile() {
        stubUsersResource();
        UUID userId = UUID.randomUUID();
        UserRepresentation user = new UserRepresentation();
        user.setFirstName("An");
        user.setLastName("Nguyen");
        user.setEmail("student01@example.com");
        user.setEmailVerified(true);
        when(usersResource.get(userId.toString())).thenReturn(userResource);
        when(userResource.toRepresentation()).thenReturn(user);

        IdentityUserProfileSnapshot snapshot = client.updateUserProfile(
                userId,
                "Truong An",
                "Tran",
                "new.student@example.com");

        verify(userResource).update(userCaptor.capture());
        assertThat(userCaptor.getValue().getFirstName()).isEqualTo("Truong An");
        assertThat(userCaptor.getValue().getLastName()).isEqualTo("Tran");
        assertThat(userCaptor.getValue().getEmail()).isEqualTo("new.student@example.com");
        assertThat(userCaptor.getValue().isEmailVerified()).isFalse();
        assertThat(snapshot).isEqualTo(new IdentityUserProfileSnapshot(
                "An", "Nguyen", "student01@example.com", true));
    }

    @Test
    void restoresCompleteKeycloakUserProfile() {
        stubUsersResource();
        UUID userId = UUID.randomUUID();
        UserRepresentation user = new UserRepresentation();
        when(usersResource.get(userId.toString())).thenReturn(userResource);
        when(userResource.toRepresentation()).thenReturn(user);
        IdentityUserProfileSnapshot snapshot = new IdentityUserProfileSnapshot(
                "An", "Nguyen", "student01@example.com", true);

        client.restoreUserProfileQuietly(userId, snapshot);

        verify(userResource).update(userCaptor.capture());
        assertThat(userCaptor.getValue().getFirstName()).isEqualTo("An");
        assertThat(userCaptor.getValue().getLastName()).isEqualTo("Nguyen");
        assertThat(userCaptor.getValue().getEmail()).isEqualTo("student01@example.com");
        assertThat(userCaptor.getValue().isEmailVerified()).isTrue();
    }

    @Test
    void mapsEmailConflictFromProfileUpdate() {
        stubUsersResource();
        UUID userId = UUID.randomUUID();
        UserRepresentation user = new UserRepresentation();
        user.setEmail("student01@example.com");
        when(usersResource.get(userId.toString())).thenReturn(userResource);
        when(userResource.toRepresentation()).thenReturn(user);
        when(response.getStatus()).thenReturn(Response.Status.CONFLICT.getStatusCode());
        when(response.getStatusInfo()).thenReturn(Response.Status.CONFLICT);
        doThrow(new WebApplicationException(response)).when(userResource).update(user);

        assertThatThrownBy(() -> client.updateUserProfile(
                userId, "An", "Nguyen", "existing@example.com"))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.EMAIL_EXISTS);
        verify(response).close();
    }

    @Test
    void reportsKeycloakAsUnavailableWhenProfileUpdateCannotBeSent() {
        stubUsersResource();
        UUID userId = UUID.randomUUID();
        when(usersResource.get(userId.toString())).thenReturn(userResource);
        when(userResource.toRepresentation())
                .thenThrow(new ProcessingException("connection refused"));

        assertThatThrownBy(() -> client.updateUserProfile(
                userId, "An", "Nguyen", "student01@example.com"))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.IDENTITY_PROVIDER_UNAVAILABLE);
    }

    private void stubUsersResource() {
        when(keycloak.realm("DoAn")).thenReturn(realmResource);
        when(realmResource.users()).thenReturn(usersResource);
    }

    private CreateIdentityUserCommand validRequest() {
        return new CreateIdentityUserCommand(
                "student01",
                "strong-password",
                "an@example.com",
                "An",
                "Nguyen");
    }
}
