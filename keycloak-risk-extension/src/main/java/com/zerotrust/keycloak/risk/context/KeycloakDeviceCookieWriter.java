package com.zerotrust.keycloak.risk.context;

import jakarta.ws.rs.core.NewCookie;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.utils.SecureContextResolver;

import java.time.Duration;
import java.util.Objects;

public final class KeycloakDeviceCookieWriter implements DeviceCookieWriter {

    static final int MAX_AGE_SECONDS = Math.toIntExact(Duration.ofDays(30).toSeconds());

    @Override
    public void issue(AuthenticationFlowContext context, String deviceId) {
        Objects.requireNonNull(context, "context must not be null");
        String validatedDeviceId = CookieDeviceIdResolver.validatedValue(deviceId);
        if (validatedDeviceId == null) {
            throw new IllegalArgumentException("deviceId is invalid");
        }
        setCookie(context, validatedDeviceId, MAX_AGE_SECONDS);
    }

    @Override
    public void expire(AuthenticationFlowContext context) {
        Objects.requireNonNull(context, "context must not be null");
        setCookie(context, "", 0);
    }

    private static void setCookie(
            AuthenticationFlowContext context,
            String value,
            int maxAgeSeconds
    ) {
        KeycloakSession session = context.getSession();
        String realmPath = RealmsResource.realmBaseUrl(session.getContext().getUri())
                .path("/")
                .build(context.getRealm().getName())
                .getRawPath();
        NewCookie cookie = buildCookie(
                value,
                realmPath,
                maxAgeSeconds,
                SecureContextResolver.isSecureContext(session)
        );
        session.getContext().getHttpResponse().setCookieIfAbsent(cookie);
    }

    static NewCookie buildCookie(
            String value,
            String path,
            int maxAgeSeconds,
            boolean secure
    ) {
        return new NewCookie.Builder(CookieDeviceIdResolver.COOKIE_NAME)
                .version(1)
                .value(value)
                .path(path)
                .maxAge(maxAgeSeconds)
                .secure(secure)
                .httpOnly(true)
                .sameSite(NewCookie.SameSite.LAX)
                .build();
    }
}
