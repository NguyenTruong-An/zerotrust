package com.zerotrust.zerotrust.identity.keycloak;

import com.zerotrust.zerotrust.config.KeycloakAdminProperties;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.WebApplicationException;
import lombok.RequiredArgsConstructor;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.RoleRepresentation;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class KeycloakRoleClient {
    private final Keycloak keycloak;
    private final KeycloakAdminProperties properties;
    private final KeycloakExceptionMapper exceptionMapper;

    public void assignRealmRole(UUID userId, String roleName) {
        try {
            RealmResource realm = keycloak.realm(properties.realm());
            RoleRepresentation role = realm.roles()
                    .get(roleName)
                    .toRepresentation();
            realm.users()
                    .get(userId.toString())
                    .roles()
                    .realmLevel()
                    .add(List.of(role));
        } catch (ProcessingException ex) {
            throw exceptionMapper.providerUnavailable();
        } catch (WebApplicationException ex) {
            throw exceptionMapper.mapRoleFailure(ex, roleName);
        }
    }
}
