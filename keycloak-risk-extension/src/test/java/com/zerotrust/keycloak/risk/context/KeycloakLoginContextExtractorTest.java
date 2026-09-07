package com.zerotrust.keycloak.risk.context;

import jakarta.ws.rs.core.HttpHeaders;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.ClientConnection;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.ClientModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class KeycloakLoginContextExtractorTest {

    @Test
    void extractsServerObservedLoginContext() {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        UserModel user = mock(UserModel.class);
        AuthenticationSessionModel authenticationSession = mock(AuthenticationSessionModel.class);
        RootAuthenticationSessionModel rootSession = mock(RootAuthenticationSessionModel.class);
        ClientModel client = mock(ClientModel.class);
        ClientConnection connection = mock(ClientConnection.class);
        HttpRequest request = mock(HttpRequest.class);
        HttpHeaders headers = mock(HttpHeaders.class);
        DeviceIdResolver deviceIdResolver = mock(DeviceIdResolver.class);

        when(context.getUser()).thenReturn(user);
        when(user.getId()).thenReturn("user-1");
        when(context.getAuthenticationSession()).thenReturn(authenticationSession);
        when(authenticationSession.getParentSession()).thenReturn(rootSession);
        when(rootSession.getId()).thenReturn("root-session");
        when(authenticationSession.getTabId()).thenReturn("tab-1");
        when(authenticationSession.getClient()).thenReturn(client);
        when(client.getClientId()).thenReturn("zerotrust-spa");
        when(context.getConnection()).thenReturn(connection);
        when(connection.getRemoteAddr()).thenReturn("203.0.113.10");
        when(context.getHttpRequest()).thenReturn(request);
        when(request.getHttpHeaders()).thenReturn(headers);
        when(headers.getHeaderString("User-Agent")).thenReturn("Mozilla/5.0");
        when(deviceIdResolver.resolve(context)).thenReturn("device-123");

        var result = new KeycloakLoginContextExtractor(
                deviceIdResolver
        ).extract(context);

        assertEquals("user-1", result.subjectId());
        assertEquals("root-session:tab-1", result.authenticationSessionId());
        assertEquals("zerotrust-spa", result.clientId());
        assertEquals("203.0.113.10", result.ipAddress());
        assertEquals("Mozilla/5.0", result.userAgent());
        assertEquals("device-123", result.deviceId());
    }

    @Test
    void ignoresInvalidDeviceCookie() {
        assertNull(CookieDeviceIdResolver.validatedValue("bad value containing spaces"));
    }
}
