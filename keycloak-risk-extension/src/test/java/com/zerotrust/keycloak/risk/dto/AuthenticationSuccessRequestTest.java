package com.zerotrust.keycloak.risk.dto;

import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class AuthenticationSuccessRequestTest {
    @Test void legacyWireContractOmitsAbsentCorrelation() throws Exception {
        var request = new AuthenticationSuccessRequest("synthetic-event", "synthetic-subject", "zerotrust-spa", Instant.parse("2026-11-12T00:00:00Z"));
        Map<?, ?> body = JsonSerialization.readValue(JsonSerialization.writeValueAsString(request), Map.class);
        assertEquals(4, body.size());
        assertFalse(body.containsKey("riskEvaluationId"));
        assertEquals("2026-11-12T00:00:00Z", body.get("authenticatedAt"));
    }
    @Test void correlationRoundTripsAsUuidWithoutAdditionalNetworkOrCredentialClaims() throws Exception {
        UUID id = UUID.randomUUID();
        var request = new AuthenticationSuccessRequest("synthetic-event", "synthetic-subject", "zerotrust-spa", Instant.parse("2026-11-12T00:00:00Z"), id);
        Map<?, ?> body = JsonSerialization.readValue(JsonSerialization.writeValueAsString(request), Map.class);
        assertEquals(5, body.size()); assertEquals(id.toString(), body.get("riskEvaluationId"));
        var decoded = JsonSerialization.readValue(JsonSerialization.writeValueAsString(request), AuthenticationSuccessRequest.class);
        assertEquals(request, decoded);
    }
}
