package com.zerotrust.zerotrust.identity;

import com.zerotrust.zerotrust.identity.model.CreateIdentityUserCommand;
import com.zerotrust.zerotrust.identity.model.IdentityUserProfileSnapshot;
import com.zerotrust.zerotrust.identity.model.ProvisionedIdentityUser;

import java.util.UUID;

public interface IdentityProviderGateway {
    ProvisionedIdentityUser createUser(CreateIdentityUserCommand command);

    void assignRealmRole(UUID userId, String roleName);

    void deleteUserQuietly(ProvisionedIdentityUser provisionedUser);

    IdentityUserProfileSnapshot updateUserProfile(
            UUID userId,
            String firstName,
            String lastName,
            String email);

    void restoreUserProfileQuietly(
            UUID userId,
            IdentityUserProfileSnapshot profile);
}
