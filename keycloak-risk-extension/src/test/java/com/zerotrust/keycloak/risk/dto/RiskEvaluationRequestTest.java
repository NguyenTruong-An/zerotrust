package com.zerotrust.keycloak.risk.dto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RiskEvaluationRequestTest {

    @Test
    void acceptsOptionalBrowserSignalsWhenMissing() {
        assertDoesNotThrow(() -> new RiskEvaluationRequest(
                "user-1",
                "session-1",
                "zerotrust-spa",
                "203.0.113.10",
                null,
                null
        ));
    }

    @Test
    void rejectsBlankRequiredContext() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new RiskEvaluationRequest(
                        " ",
                        "session-1",
                        "zerotrust-spa",
                        "203.0.113.10",
                        null,
                        null
                )
        );
    }
}
