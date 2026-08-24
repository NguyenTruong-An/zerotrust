package com.zerotrust.zerotrust.identity.model;

public record CreateIdentityUserCommand(
        String username,
        String password,
        String email,
        String firstName,
        String lastName
) {
}
