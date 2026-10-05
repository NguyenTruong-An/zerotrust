package com.zerotrust.zerotrust.risk;

import com.fasterxml.jackson.databind.JsonNode;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.net.http.HttpClient;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Component
public class RiskDeviceAdminClient {
    private final RiskAdminProperties properties;
    private final RestClient client;
    private String cachedToken;
    private Instant refreshAt = Instant.EPOCH;

    @Autowired
    public RiskDeviceAdminClient(RiskAdminProperties properties) {
        this(properties, buildClient(properties));
    }

    RiskDeviceAdminClient(RiskAdminProperties properties, RestClient client) {
        this.properties = properties;
        this.client = client;
    }

    private static RestClient buildClient(RiskAdminProperties properties) {
        var http = HttpClient.newBuilder().connectTimeout(properties.getConnectTimeout())
                .followRedirects(HttpClient.Redirect.NEVER).build();
        var factory = new JdkClientHttpRequestFactory(http);
        factory.setReadTimeout(properties.getReadTimeout());
        return RestClient.builder().requestFactory(factory).build();
    }

    public void revoke(UUID subjectId, UUID operationId, String requestedBy) {
        send(subjectId, operationId, requestedBy, "");
    }

    public void complete(UUID subjectId, UUID operationId, String requestedBy) {
        send(subjectId, operationId, requestedBy, "/completion");
    }

    private void send(UUID subjectId, UUID operationId, String requestedBy, String suffix) {
        if (!properties.configured()) throw new WebException(ErrorCode.RISK_DEVICE_REVOCATION_FAILED);
        String endpoint = properties.getBaseUrl().toString().replaceAll("/+$", "")
                + "/internal/v1/subjects/" + subjectId + "/trusted-devices/revocations" + suffix;
        var body = Map.of("operationId", operationId.toString(), "requestedBy", requestedBy);
        try {
            for (int attempt = 0; attempt < 2; attempt++) {
                String token = accessToken();
                try {
                    var response = client.post().uri(endpoint)
                            .headers(headers -> headers.setBearerAuth(token))
                            .contentType(MediaType.APPLICATION_JSON).body(body).retrieve().toBodilessEntity();
                    if (response.getStatusCode().value() != 204) throw new IllegalStateException("Unexpected status");
                    return;
                } catch (RestClientResponseException ex) {
                    if (ex.getStatusCode().value() != 401 || attempt != 0) throw ex;
                    invalidate(token);
                }
            }
        } catch (RuntimeException ex) {
            // Do not expose token responses, request bodies, secrets or remote error bodies.
            throw new WebException(ErrorCode.RISK_DEVICE_REVOCATION_FAILED);
        }
    }

    private synchronized String accessToken() {
        if (cachedToken != null && Instant.now().isBefore(refreshAt)) return cachedToken;
        var form = new LinkedMultiValueMap<String, String>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", properties.getClientId());
        form.add("client_secret", properties.getClientSecret());
        JsonNode response = client.post().uri(properties.getTokenUri())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED).body(form).retrieve().body(JsonNode.class);
        if (response == null || !response.path("access_token").isTextual()
                || response.path("access_token").asText().isBlank()
                || !"Bearer".equalsIgnoreCase(response.path("token_type").asText())
                || response.path("expires_in").asLong() <= 0) {
            throw new IllegalStateException("Invalid service-token response");
        }
        cachedToken = response.path("access_token").asText();
        refreshAt = Instant.now().plusSeconds(Math.max(0, Math.min(3600, response.path("expires_in").asLong()) - 30));
        return cachedToken;
    }

    private synchronized void invalidate(String token) {
        if (token.equals(cachedToken)) {
            cachedToken = null;
            refreshAt = Instant.EPOCH;
        }
    }
}
