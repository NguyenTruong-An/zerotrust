package com.zerotrust.zerotrust.identity.keycloak;

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
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KeycloakRoleClientTest {
    @Mock
    private Keycloak keycloak;
    @Mock
    private RealmResource realmResource;
    @Mock
    private RolesResource rolesResource;
    @Mock
    private RoleResource roleResource;
    @Mock
    private UsersResource usersResource;
    @Mock
    private UserResource userResource;
    @Mock
    private RoleMappingResource roleMappingResource;
    @Mock
    private RoleScopeResource roleScopeResource;
    @Mock
    private Response response;

    private KeycloakRoleClient client;

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
        client = new KeycloakRoleClient(
                keycloak,
                properties,
                new KeycloakExceptionMapper());
    }

    @Test
    void assignsRealmRoleToUser() {
        UUID userId = UUID.randomUUID();
        RoleRepresentation studentRole = new RoleRepresentation();
        studentRole.setName("STUDENT");
        stubRoleLookup();
        when(roleResource.toRepresentation()).thenReturn(studentRole);
        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.get(userId.toString())).thenReturn(userResource);
        when(userResource.roles()).thenReturn(roleMappingResource);
        when(roleMappingResource.realmLevel()).thenReturn(roleScopeResource);

        client.assignRealmRole(userId, "STUDENT");

        verify(roleScopeResource).add(List.of(studentRole));
    }

    @Test
    void reportsMissingRealmRole() {
        UUID userId = UUID.randomUUID();
        stubRoleLookup();
        when(response.getStatus()).thenReturn(Response.Status.NOT_FOUND.getStatusCode());
        when(response.getStatusInfo()).thenReturn(Response.Status.NOT_FOUND);
        WebApplicationException notFound = new WebApplicationException(response);
        when(roleResource.toRepresentation()).thenThrow(notFound);

        assertThatThrownBy(() -> client.assignRealmRole(userId, "STUDENT"))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.IDENTITY_ROLE_NOT_FOUND);
        verify(response).close();
    }

    @Test
    void reportsKeycloakAsUnavailableWhenRoleCannotBeRead() {
        UUID userId = UUID.randomUUID();
        stubRoleLookup();
        when(roleResource.toRepresentation())
                .thenThrow(new ProcessingException("connection refused"));

        assertThatThrownBy(() -> client.assignRealmRole(userId, "STUDENT"))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.IDENTITY_PROVIDER_UNAVAILABLE);
    }

    private void stubRoleLookup() {
        when(keycloak.realm("DoAn")).thenReturn(realmResource);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.get("STUDENT")).thenReturn(roleResource);
    }
}
