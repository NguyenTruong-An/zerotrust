package com.zerotrust.zerotrust.identity.model;

public record IdentityUserProfileSnapshot(
        String firstName,
        String lastName,
        String email,
        Boolean emailVerified
) {
}
