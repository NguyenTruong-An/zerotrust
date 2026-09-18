package com.zerotrust.keycloak.risk.context;

import jakarta.ws.rs.core.NewCookie;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeycloakDeviceCookieWriterTest {

    @Test
    void buildsRealmScopedHttpOnlyLaxCookie() {
        NewCookie cookie = KeycloakDeviceCookieWriter.buildCookie(
                "device-123",
                "/realms/DoAn/",
                KeycloakDeviceCookieWriter.MAX_AGE_SECONDS,
                true
        );

        assertEquals(CookieDeviceIdResolver.COOKIE_NAME, cookie.getName());
        assertEquals("device-123", cookie.getValue());
        assertEquals("/realms/DoAn/", cookie.getPath());
        assertEquals(KeycloakDeviceCookieWriter.MAX_AGE_SECONDS, cookie.getMaxAge());
        assertEquals(NewCookie.SameSite.LAX, cookie.getSameSite());
        assertTrue(cookie.isHttpOnly());
        assertTrue(cookie.isSecure());
    }

    @Test
    void developmentCookieKeepsSecurityFlagsExceptSecureOnHttp() {
        NewCookie cookie = KeycloakDeviceCookieWriter.buildCookie(
                "device-123",
                "/realms/DoAn/",
                KeycloakDeviceCookieWriter.MAX_AGE_SECONDS,
                false
        );

        assertTrue(cookie.isHttpOnly());
        assertEquals(NewCookie.SameSite.LAX, cookie.getSameSite());
        assertFalse(cookie.isSecure());
    }
}
