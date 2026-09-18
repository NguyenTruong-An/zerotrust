package com.zerotrust.keycloak.risk.listener;

import com.zerotrust.keycloak.risk.client.AuthenticationEventClient;
import com.zerotrust.keycloak.risk.client.AuthenticationEventClientFactory;
import com.zerotrust.keycloak.risk.client.RiskScoringClientException;
import com.zerotrust.keycloak.risk.config.BrowserFlowRiskConfigLocator;
import com.zerotrust.keycloak.risk.config.RiskEventListenerConfig;
import com.zerotrust.keycloak.risk.config.RiskEventListenerConfigResolver;
import com.zerotrust.keycloak.risk.dto.AuthenticationFailureRequest;
import com.zerotrust.keycloak.risk.dto.AuthenticationSuccessRequest;
import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public final class RiskEventListener implements EventListenerProvider {

    private static final Logger LOGGER = Logger.getLogger(RiskEventListener.class);

    private final KeycloakSession session;
    private final BrowserFlowRiskConfigLocator configLocator;
    private final RiskEventListenerConfigResolver configResolver;
    private final AuthenticationEventClientFactory clientFactory;

    public RiskEventListener(
            KeycloakSession session,
            BrowserFlowRiskConfigLocator configLocator,
            RiskEventListenerConfigResolver configResolver,
            AuthenticationEventClientFactory clientFactory
    ) {
        this.session = Objects.requireNonNull(session, "session must not be null");
        this.configLocator = Objects.requireNonNull(
                configLocator,
                "configLocator must not be null"
        );
        this.configResolver = Objects.requireNonNull(
                configResolver,
                "configResolver must not be null"
        );
        this.clientFactory = Objects.requireNonNull(
                clientFactory,
                "clientFactory must not be null"
        );
    }

    @Override
    public void onEvent(Event event) {
        if (event == null || !isSupported(event.getType())) {
            return;
        }

        try {
            RealmModel realm = session.realms().getRealm(event.getRealmId());
            AuthenticatorConfigModel authenticatorConfig = configLocator.locate(realm);
            RiskEventListenerConfig config = configResolver.resolve(authenticatorConfig);
            if (!config.monitoredClientId().equals(event.getClientId())) {
                return;
            }

            AuthenticationEventClient client = clientFactory.create(config.riskConfig());
            if (event.getType() == EventType.LOGIN_ERROR) {
                recordFailure(event, client);
            } else {
                recordSuccess(event, client);
            }
        } catch (RuntimeException exception) {
            // Telemetry must never change Keycloak's authentication result.
            if (exception instanceof RiskScoringClientException clientException) {
                LOGGER.warnf(
                        "Failed to send ZeroTrust authentication event: "
                                + "realm=%s, client=%s, type=%s, status=%d",
                        event.getRealmId(),
                        event.getClientId(),
                        clientException.failureType(),
                        clientException.statusCode()
                );
            } else {
                LOGGER.warnf(
                        "Failed to send ZeroTrust authentication event: "
                                + "realm=%s, client=%s, reason=%s",
                        event.getRealmId(),
                        event.getClientId(),
                        exception.getClass().getSimpleName()
                );
            }
        }
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        // Admin events do not contribute to the browser authentication history.
    }

    @Override
    public void close() {
        // Keycloak owns the session and managed HTTP client.
    }

    private static boolean isSupported(EventType eventType) {
        return eventType == EventType.LOGIN_ERROR || eventType == EventType.LOGIN;
    }

    private static void recordFailure(Event event, AuthenticationEventClient client) {
        String sourceIp = optionalText(event.getIpAddress());
        if (sourceIp == null) {
            LOGGER.warnf(
                    "Skipped ZeroTrust authentication failure without source IP "
                            + "for realm %s and client %s",
                    event.getRealmId(),
                    event.getClientId()
            );
            return;
        }
        client.recordFailure(new AuthenticationFailureRequest(
                eventId(event),
                optionalText(event.getUserId()),
                sourceIp
        ));
    }

    private static void recordSuccess(Event event, AuthenticationEventClient client) {
        String subjectId = optionalText(event.getUserId());
        if (subjectId == null || event.getTime() <= 0) {
            LOGGER.warnf(
                    "Skipped ZeroTrust authentication success without subject or event time "
                            + "for realm %s and client %s",
                    event.getRealmId(),
                    event.getClientId()
            );
            return;
        }
        client.recordSuccess(new AuthenticationSuccessRequest(
                eventId(event),
                subjectId,
                event.getClientId(),
                Instant.ofEpochMilli(event.getTime())
        ));
    }

    private static String eventId(Event event) {
        String id = optionalText(event.getId());
        return id == null ? UUID.randomUUID().toString() : id;
    }

    private static String optionalText(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
