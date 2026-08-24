package com.zerotrust.zerotrust.identity.keycloak;

import com.zerotrust.zerotrust.identity.IdentityProviderGateway;
import com.zerotrust.zerotrust.identity.model.CreateIdentityUserCommand;
import com.zerotrust.zerotrust.identity.model.IdentityUserProfileSnapshot;
import com.zerotrust.zerotrust.identity.model.ProvisionedIdentityUser;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
public class KeycloakIdentityProviderGateway implements IdentityProviderGateway {
    private final KeycloakUserClient userClient;
    private final KeycloakRoleClient roleClient;

    @Override
    public ProvisionedIdentityUser createUser(CreateIdentityUserCommand command) {
        return userClient.createUser(command);
    }

    @Override
    public void assignRealmRole(UUID userId, String roleName) {
        roleClient.assignRealmRole(userId, roleName);
    }

    @Override
    public void deleteUserQuietly(ProvisionedIdentityUser provisionedUser) {
        userClient.deleteUserQuietly(provisionedUser);
    }

    @Override
    public IdentityUserProfileSnapshot updateUserProfile(
            UUID userId,
            String firstName,
            String lastName,
            String email) {
        return userClient.updateUserProfile(userId, firstName, lastName, email);
    }

    @Override
    public void restoreUserProfileQuietly(
            UUID userId,
            IdentityUserProfileSnapshot profile) {
        userClient.restoreUserProfileQuietly(userId, profile);
    }
}
