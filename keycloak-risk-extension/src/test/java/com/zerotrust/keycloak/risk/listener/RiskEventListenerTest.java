package com.zerotrust.keycloak.risk.listener;

import com.zerotrust.keycloak.risk.client.AuthenticationEventClient;
import com.zerotrust.keycloak.risk.client.AuthenticationEventClientFactory;
import com.zerotrust.keycloak.risk.config.BrowserFlowRiskConfigLocator;
import com.zerotrust.keycloak.risk.config.RiskAuthenticatorConfig;
import com.zerotrust.keycloak.risk.config.RiskEventListenerConfig;
import com.zerotrust.keycloak.risk.config.RiskEventListenerConfigResolver;
import com.zerotrust.keycloak.risk.dto.AuthenticationFailureRequest;
import com.zerotrust.keycloak.risk.dto.AuthenticationSuccessRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.mockito.ArgumentCaptor;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class RiskEventListenerTest {

    private final KeycloakSession session = mock(KeycloakSession.class);
    private final RealmProvider realmProvider = mock(RealmProvider.class);
    private final RealmModel realm = mock(RealmModel.class);
    private final BrowserFlowRiskConfigLocator configLocator =
            mock(BrowserFlowRiskConfigLocator.class);
    private final RiskEventListenerConfigResolver configResolver =
            mock(RiskEventListenerConfigResolver.class);
    private final AuthenticationEventClientFactory clientFactory =
            mock(AuthenticationEventClientFactory.class);
    private final AuthenticationEventClient client = mock(AuthenticationEventClient.class);
    private final RiskAuthenticatorConfig riskConfig = mock(RiskAuthenticatorConfig.class);

    private RiskEventListener listener;
    private AuthenticatorConfigModel authenticatorConfig;

    @BeforeEach
    void setUp() {
        authenticatorConfig = new AuthenticatorConfigModel();
        listener = new RiskEventListener(
                session,
                configLocator,
                configResolver,
                clientFactory
        );
    }

    @Test
    void forwardsPortalLoginErrorAndAllowsUnknownSubject() {
        prepareConfig("zerotrust-spa");
        when(clientFactory.create(riskConfig)).thenReturn(client);
        Event event = loginEvent(EventType.LOGIN_ERROR, "zerotrust-spa");
        event.setId("event-1");
        event.setUserId(null);

        listener.onEvent(event);

        ArgumentCaptor<AuthenticationFailureRequest> request =
                ArgumentCaptor.forClass(AuthenticationFailureRequest.class);
        verify(client).recordFailure(request.capture());
        assertEquals("event-1", request.getValue().eventId());
        assertNull(request.getValue().subjectId());
        assertEquals("203.0.113.10", request.getValue().sourceIp());
    }

    @Test
    void forwardsPortalLoginSuccessWithKeycloakEventTime() {
        prepareConfig("zerotrust-spa");
        when(clientFactory.create(riskConfig)).thenReturn(client);
        Event event = loginEvent(EventType.LOGIN, "zerotrust-spa");
        event.setId("event-2");
        event.setUserId("user-1");
        event.setTime(Instant.parse("2026-09-17T03:00:00Z").toEpochMilli());

        listener.onEvent(event);

        ArgumentCaptor<AuthenticationSuccessRequest> request =
                ArgumentCaptor.forClass(AuthenticationSuccessRequest.class);
        verify(client).recordSuccess(request.capture());
        assertEquals("event-2", request.getValue().eventId());
        assertEquals("user-1", request.getValue().subjectId());
        assertEquals("zerotrust-spa", request.getValue().clientId());
        assertEquals(
                Instant.parse("2026-09-17T03:00:00Z"),
                request.getValue().authenticatedAt()
        );
    }

    @Test
    void skipsMalformedLoginSuccessWithoutSendingAnEvent() {
        prepareConfig("zerotrust-spa");
        when(clientFactory.create(riskConfig)).thenReturn(client);
        Event event = loginEvent(EventType.LOGIN, "zerotrust-spa");
        event.setUserId(null);
        event.setTime(0);

        listener.onEvent(event);

        verifyNoInteractions(client);
    }

    @Test
    void ignoresUnrelatedEventWithoutResolvingConfiguration() {
        Event event = loginEvent(EventType.LOGOUT, "zerotrust-spa");

        listener.onEvent(event);

        verifyNoInteractions(configLocator, configResolver, clientFactory, client);
    }

    @Test
    void ignoresAuthenticationEventFromAnotherClient() {
        prepareConfig("zerotrust-spa");

        listener.onEvent(loginEvent(EventType.LOGIN, "security-admin-console"));

        verify(clientFactory, never()).create(riskConfig);
        verifyNoInteractions(client);
    }

    @Test
    void telemetryFailureNeverChangesAuthenticationResult() {
        when(session.realms()).thenReturn(realmProvider);
        when(realmProvider.getRealm("realm-1")).thenThrow(new IllegalStateException("offline"));

        assertDoesNotThrow(() -> listener.onEvent(
                loginEvent(EventType.LOGIN_ERROR, "zerotrust-spa")
        ));
        verifyNoInteractions(client);
    }

    private void prepareConfig(String monitoredClientId) {
        when(session.realms()).thenReturn(realmProvider);
        when(realmProvider.getRealm("realm-1")).thenReturn(realm);
        when(configLocator.locate(realm)).thenReturn(authenticatorConfig);
        when(configResolver.resolve(authenticatorConfig))
                .thenReturn(new RiskEventListenerConfig(riskConfig, monitoredClientId));
    }

    private static Event loginEvent(EventType eventType, String clientId) {
        Event event = new Event();
        event.setType(eventType);
        event.setRealmId("realm-1");
        event.setClientId(clientId);
        event.setIpAddress("203.0.113.10");
        return event;
    }
}
