package com.zerotrust.zerotrust.model.response;

import java.util.List;

public record AuthSessionResponse(
        boolean authenticated,
        String username,
        List<String> roles
) {
    public static AuthSessionResponse unauthenticated() {
        return new AuthSessionResponse(false, null, List.of());
    }
}
