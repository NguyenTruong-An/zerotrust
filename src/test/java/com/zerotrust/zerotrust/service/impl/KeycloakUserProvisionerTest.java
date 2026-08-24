package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.config.KeycloakAdminProperties;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleMappingResource;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.admin.client.resource.RoleScopeResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.RoleRepresentation;
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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KeycloakUserProvisionerTest {

    @Mock
    private Keycloak keycloak;
    @Mock
    private RealmResource realmResource;
    @Mock
    private UsersResource usersResource;
    @Mock
    private UserResource userResource;
    @Mock
    private RolesResource rolesResource;
    @Mock
    private RoleResource roleResource;
    @Mock
    private RoleMappingResource roleMappingResource;
    @Mock
    private RoleScopeResource roleScopeResource;
    @Mock
    private Response response;
    @Captor
    private ArgumentCaptor<UserRepresentation> userCaptor;

    private KeycloakUserProvisioner provisioner;

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
        provisioner = new KeycloakUserProvisioner(keycloak, properties);
    }

    @Test
    void createsUserAndReturnsCreatedId() {
        stubUsersResource();
        KeycloakUserProvisioner.CreateUserCommand request = validRequest();
        UUID userId = UUID.randomUUID();
        when(response.getStatus()).thenReturn(Response.Status.CREATED.getStatusCode());
        when(response.getStatusInfo()).thenReturn(Response.Status.CREATED);
        when(response.getLocation()).thenReturn(
                URI.create("http://localhost/admin/realms/DoAn/users/" + userId));
        when(usersResource.create(any())).thenReturn(response);

        assertThat(provisioner.createUser(request).userId()).isEqualTo(userId);

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
        KeycloakUserProvisioner.CreateUserCommand request = validRequest();
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

        assertThatThrownBy(() -> provisioner.createUser(request))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.IDENTITY_RESPONSE_INVALID);
        verify(userResource).remove();
    }

    @Test
    void mapsEmailConflictFromKeycloak() {
        stubUsersResource();
        when(response.getStatus()).thenReturn(Response.Status.CONFLICT.getStatusCode());
        when(response.hasEntity()).thenReturn(true);
        when(response.readEntity(String.class))
                .thenReturn("User exists with same email");
        when(usersResource.create(any())).thenReturn(response);

        assertThatThrownBy(() -> provisioner.createUser(validRequest()))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.EMAIL_EXISTS);
    }

    @Test
    void reportsKeycloakAsUnavailableWhenRequestCannotBeSent() {
        stubUsersResource();
        when(usersResource.create(any()))
                .thenThrow(new ProcessingException("connection refused"));

        assertThatThrownBy(() -> provisioner.createUser(validRequest()))
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
        when(usersResource.create(any()))
                .thenThrow(unauthorized);

        assertThatThrownBy(() -> provisioner.createUser(validRequest()))
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

        provisioner.deleteUserQuietly(new KeycloakUserProvisioner.ProvisionedUser(userId));

        verify(userResource).remove();
    }

    @Test
    void assignsRealmRoleToProvisionedUser() {
        stubUsersResource();
        UUID userId = UUID.randomUUID();
        RoleRepresentation studentRole = new RoleRepresentation();
        studentRole.setName("STUDENT");
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.get("STUDENT")).thenReturn(roleResource);
        when(roleResource.toRepresentation()).thenReturn(studentRole);
        when(usersResource.get(userId.toString())).thenReturn(userResource);
        when(userResource.roles()).thenReturn(roleMappingResource);
        when(roleMappingResource.realmLevel()).thenReturn(roleScopeResource);

        provisioner.assignRealmRole(userId, "STUDENT");

        verify(roleScopeResource).add(List.of(studentRole));
    }

    @Test
    void ignoresNullProvisionedUserDuringRollback() {
        provisioner.deleteUserQuietly(null);

        verify(usersResource, never()).get(any());
    }

    @Test
    void updatesKeycloakUserProfile() {
        stubUsersResource();
        UUID userId = UUID.randomUUID();
        UserRepresentation user = new UserRepresentation();
        user.setFirstName("An");
        user.setLastName("Nguyen");
        when(usersResource.get(userId.toString())).thenReturn(userResource);
        when(userResource.toRepresentation()).thenReturn(user);

        provisioner.updateUserProfile(userId, "Truong An", "Tran");

        verify(userResource).update(userCaptor.capture());
        assertThat(userCaptor.getValue().getFirstName()).isEqualTo("Truong An");
        assertThat(userCaptor.getValue().getLastName()).isEqualTo("Tran");
    }

    @Test
    void reportsKeycloakAsUnavailableWhenProfileUpdateCannotBeSent() {
        stubUsersResource();
        UUID userId = UUID.randomUUID();
        when(usersResource.get(userId.toString())).thenReturn(userResource);
        when(userResource.toRepresentation())
                .thenThrow(new ProcessingException("connection refused"));

        assertThatThrownBy(() -> provisioner.updateUserProfile(userId, "An", "Nguyen"))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.IDENTITY_PROVIDER_UNAVAILABLE);
    }

    private void stubUsersResource() {
        when(keycloak.realm("DoAn")).thenReturn(realmResource);
        when(realmResource.users()).thenReturn(usersResource);
    }

    private KeycloakUserProvisioner.CreateUserCommand validRequest() {
        return new KeycloakUserProvisioner.CreateUserCommand(
                "student01",
                "strong-password",
                "an@example.com",
                "An",
                "Nguyen");
    }
}
