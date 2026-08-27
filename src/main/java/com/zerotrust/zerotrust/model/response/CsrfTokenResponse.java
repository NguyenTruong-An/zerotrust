package com.zerotrust.zerotrust.model.response;

public record CsrfTokenResponse(
        String token,
        String headerName,
        String parameterName
) {
}
