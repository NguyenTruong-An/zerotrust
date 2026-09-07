package com.zerotrust.keycloak.risk.client;

public final class RiskScoringClientException extends RuntimeException {

    private final FailureType failureType;
    private final int statusCode;

    private RiskScoringClientException(
            FailureType failureType,
            String message,
            int statusCode,
            Throwable cause
    ) {
        super(message, cause);
        this.failureType = failureType;
        this.statusCode = statusCode;
    }

    static RiskScoringClientException serialization(Throwable cause) {
        return new RiskScoringClientException(
                FailureType.SERIALIZATION_FAILURE,
                "Could not serialize the risk evaluation request",
                -1,
                cause
        );
    }

    static RiskScoringClientException timeout(Throwable cause) {
        return new RiskScoringClientException(
                FailureType.TIMEOUT,
                "Risk Scoring Service did not respond before the timeout",
                -1,
                cause
        );
    }

    static RiskScoringClientException interrupted(Throwable cause) {
        return new RiskScoringClientException(
                FailureType.INTERRUPTED,
                "Risk evaluation request was interrupted",
                -1,
                cause
        );
    }

    static RiskScoringClientException connection(Throwable cause) {
        return new RiskScoringClientException(
                FailureType.CONNECTION_FAILURE,
                "Could not reach the Risk Scoring Service",
                -1,
                cause
        );
    }

    static RiskScoringClientException httpStatus(int statusCode) {
        return new RiskScoringClientException(
                FailureType.HTTP_ERROR,
                "Risk Scoring Service returned HTTP " + statusCode,
                statusCode,
                null
        );
    }

    static RiskScoringClientException invalidResponse(String message, Throwable cause) {
        return new RiskScoringClientException(
                FailureType.INVALID_RESPONSE,
                message,
                -1,
                cause
        );
    }

    public FailureType failureType() {
        return failureType;
    }

    public int statusCode() {
        return statusCode;
    }

    public enum FailureType {
        SERIALIZATION_FAILURE,
        CONNECTION_FAILURE,
        TIMEOUT,
        INTERRUPTED,
        HTTP_ERROR,
        INVALID_RESPONSE
    }
}
