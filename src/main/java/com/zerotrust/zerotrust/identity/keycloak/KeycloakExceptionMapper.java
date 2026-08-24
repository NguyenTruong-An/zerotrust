package com.zerotrust.zerotrust.identity.keycloak;

import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.springframework.stereotype.Component;

import java.util.Locale;

@Component
public class KeycloakExceptionMapper {
    public WebException mapCreateFailure(Response response) {
        int status = response.getStatus();
        if (status == Response.Status.CONFLICT.getStatusCode()) {
            String responseBody = readResponseBody(response).toLowerCase(Locale.ROOT);
            if (responseBody.contains("email")) {
                return new WebException(ErrorCode.EMAIL_EXISTS);
            }
            if (responseBody.contains("username")) {
                return new WebException(ErrorCode.USERNAME_EXISTS);
            }
            return new WebException(
                    ErrorCode.INVALID_REQUEST,
                    "Username or email already exists");
        }
        if (status == Response.Status.UNAUTHORIZED.getStatusCode()
                || status == Response.Status.FORBIDDEN.getStatusCode()) {
            return new WebException(ErrorCode.IDENTITY_PROVIDER_FORBIDDEN);
        }
        if (status >= 500) {
            return providerUnavailable();
        }
        return invalidResponse();
    }

    public WebException mapClientFailure(WebApplicationException exception) {
        Response response = exception.getResponse();
        if (response == null) {
            return invalidResponse();
        }

        try (response) {
            int status = response.getStatus();
            if (status == Response.Status.UNAUTHORIZED.getStatusCode()
                    || status == Response.Status.FORBIDDEN.getStatusCode()) {
                return new WebException(ErrorCode.IDENTITY_PROVIDER_FORBIDDEN);
            }
            if (status >= 500) {
                return providerUnavailable();
            }
            return invalidResponse();
        }
    }

    public WebException mapProfileUpdateFailure(WebApplicationException exception) {
        Response response = exception.getResponse();
        if (response != null
                && response.getStatus() == Response.Status.CONFLICT.getStatusCode()) {
            response.close();
            return new WebException(ErrorCode.EMAIL_EXISTS);
        }
        return mapClientFailure(exception);
    }

    public WebException mapRoleFailure(
            WebApplicationException exception,
            String roleName) {
        Response response = exception.getResponse();
        if (response != null
                && response.getStatus() == Response.Status.NOT_FOUND.getStatusCode()) {
            response.close();
            return new WebException(
                    ErrorCode.IDENTITY_ROLE_NOT_FOUND,
                    "Realm role " + roleName + " is not configured");
        }
        return mapClientFailure(exception);
    }

    public WebException providerUnavailable() {
        return new WebException(ErrorCode.IDENTITY_PROVIDER_UNAVAILABLE);
    }

    public WebException invalidResponse() {
        return new WebException(ErrorCode.IDENTITY_RESPONSE_INVALID);
    }

    private String readResponseBody(Response response) {
        try {
            return response.hasEntity() ? response.readEntity(String.class) : "";
        } catch (RuntimeException ignored) {
            return "";
        }
    }
}
