package com.zerotrust.keycloak.risk.context;

import com.zerotrust.keycloak.risk.dto.RiskEvaluationRequest;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.ClientModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import java.util.Objects;

public final class KeycloakLoginContextExtractor implements LoginContextExtractor {

    private static final int MAX_USER_AGENT_LENGTH = 1024;

    private final DeviceIdResolver deviceIdResolver;

    public KeycloakLoginContextExtractor(DeviceIdResolver deviceIdResolver) {
        this.deviceIdResolver = Objects.requireNonNull(
                deviceIdResolver,
                "deviceIdResolver must not be null"
        );
    }

    @Override
    public RiskEvaluationRequest extract(AuthenticationFlowContext context) {
        Objects.requireNonNull(context, "context must not be null");

        UserModel user = require(context.getUser(), "authenticated user");
        AuthenticationSessionModel authenticationSession = require(
                context.getAuthenticationSession(),
                "authentication session"
        );
        ClientModel client = require(authenticationSession.getClient(), "client");
        RootAuthenticationSessionModel rootSession = require(
                authenticationSession.getParentSession(),
                "root authentication session"
        );

        String authenticationSessionId = requireText(
                rootSession.getId(),
                "root authentication session id"
        ) + ":" + requireText(authenticationSession.getTabId(), "authentication tab id");

        return new RiskEvaluationRequest(
                requireText(user.getId(), "user id"),
                authenticationSessionId,
                requireText(client.getClientId(), "client id"),
                requireText(
                        require(context.getConnection(), "client connection").getRemoteAddr(),
                        "remote address"
                ),
                truncate(require(context.getHttpRequest(), "HTTP request")
                        .getHttpHeaders()
                        .getHeaderString("User-Agent")),
                deviceIdResolver.resolve(context)
        );
    }

    private static <T> T require(T value, String name) {
        if (value == null) {
            throw new IllegalStateException(name + " is unavailable");
        }
        return value;
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is unavailable");
        }
        return value;
    }

    private static String truncate(String value) {
        if (value == null || value.length() <= MAX_USER_AGENT_LENGTH) {
            return value;
        }
        return value.substring(0, MAX_USER_AGENT_LENGTH);
    }
}
