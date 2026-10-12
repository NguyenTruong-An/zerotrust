package com.zerotrust.zerotrust.risk;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.io.IOException;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Component
@Slf4j
public class RiskDeviceAdminClient {
    private static final int MAX_TOKEN_RESPONSE_BYTES = 64 * 1024;
    private static final long MAX_CACHE_LIFETIME_SECONDS = 3600;
    private static final long TOKEN_REFRESH_SKEW_SECONDS = 30;

    private final RiskAdminProperties properties;
    private final RestClient client;
    private final ObjectReader tokenReader;
    private final Clock clock;
    private String cachedToken;
    private Instant refreshAt = Instant.EPOCH;

    @Autowired
    public RiskDeviceAdminClient(RiskAdminProperties properties, ObjectMapper objectMapper) {
        this(properties, buildClient(properties), objectMapper, Clock.systemUTC());
    }

    RiskDeviceAdminClient(
            RiskAdminProperties properties,
            RestClient client,
            ObjectMapper objectMapper,
            Clock clock) {
        this.properties = properties;
        this.client = client;
        this.tokenReader = objectMapper.reader().with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
        this.clock = clock;
    }

    private static RestClient buildClient(RiskAdminProperties properties) {
        var http = HttpClient.newBuilder()
                .connectTimeout(properties.getConnectTimeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
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
        if (!properties.configured()) {
            log.warn("Risk admin operation={} stage=configuration: missing or invalid app.risk-admin settings; "
                    + "check dedicated credentials, endpoint URLs and allow-http for local development", operationId);
            throw new WebException(ErrorCode.RISK_DEVICE_REVOCATION_FAILED);
        }
        String endpoint = properties.getBaseUrl().toString().replaceAll("/+$", "")
                + "/internal/v1/subjects/" + subjectId + "/trusted-devices/revocations" + suffix;
        var body = Map.of("operationId", operationId.toString(), "requestedBy", requestedBy);
        String stage = "token";
        try {
            for (int attempt = 0; attempt < 2; attempt++) {
                stage = "token";
                String token = accessToken();
                stage = suffix.isEmpty() ? "revocation" : "completion";
                try {
                    client.post().uri(endpoint)
                            .headers(headers -> headers.setBearerAuth(token))
                            .contentType(MediaType.APPLICATION_JSON)
                            .body(body)
                            .exchange((request, response) -> {
                                requireStatus(response, HttpStatus.NO_CONTENT);
                                return null;
                            });
                    return;
                } catch (RestClientResponseException ex) {
                    if (ex.getStatusCode().value() != HttpStatus.UNAUTHORIZED.value()) {
                        throw ex;
                    }
                    invalidate(token);
                    if (attempt != 0) {
                        throw ex;
                    }
                }
            }
        } catch (RuntimeException ex) {
            // Do not expose token responses, request bodies, secrets or remote error bodies.
            int status = ex instanceof RestClientResponseException remote ? remote.getStatusCode().value() : -1;
            log.warn("Risk admin operation={} stage={} failureType={} status={}",
                    operationId, stage, ex.getClass().getSimpleName(), status);
            throw new WebException(ErrorCode.RISK_DEVICE_REVOCATION_FAILED);
        }
    }

    private synchronized String accessToken() {
        if (cachedToken != null && clock.instant().isBefore(refreshAt)) {
            return cachedToken;
        }

        var form = new LinkedMultiValueMap<String, String>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", properties.getClientId());
        form.add("client_secret", properties.getClientSecret());
        Instant requestedAt = clock.instant();
        JsonNode response = client.post().uri(properties.getTokenUri())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .body(form)
                .exchange((request, tokenResponse) -> readTokenResponse(tokenResponse));
        validateTokenResponse(response);

        long cacheLifetime = Math.min(MAX_CACHE_LIFETIME_SECONDS, response.path("expires_in").longValue());
        if (!clock.instant().isBefore(requestedAt.plusSeconds(cacheLifetime))) {
            throw new IllegalStateException("Service token expired before use");
        }

        // Include token-request latency in its lifetime instead of extending it after receipt.
        Instant nextRefresh = requestedAt.plusSeconds(Math.max(0, cacheLifetime - TOKEN_REFRESH_SKEW_SECONDS));
        cachedToken = response.path("access_token").textValue();
        refreshAt = nextRefresh;
        return cachedToken;
    }

    private JsonNode readTokenResponse(ClientHttpResponse response) throws IOException {
        requireStatus(response, HttpStatus.OK);
        MediaType contentType = response.getHeaders().getContentType();
        if (contentType == null || !MediaType.APPLICATION_JSON.isCompatibleWith(contentType)) {
            throw new IllegalStateException("Service-token response must be JSON");
        }
        if (response.getHeaders().getContentLength() > MAX_TOKEN_RESPONSE_BYTES) {
            throw new IllegalStateException("Service-token response exceeds its size limit");
        }

        byte[] body = response.getBody().readNBytes(MAX_TOKEN_RESPONSE_BYTES + 1);
        if (body.length > MAX_TOKEN_RESPONSE_BYTES) {
            throw new IllegalStateException("Service-token response exceeds its size limit");
        }
        return tokenReader.readTree(body);
    }

    private static void validateTokenResponse(JsonNode response) {
        if (response == null || !response.isObject()
                || !response.path("access_token").isTextual()
                || response.path("access_token").textValue().isBlank()
                || !response.path("token_type").isTextual()
                || !"Bearer".equalsIgnoreCase(response.path("token_type").textValue())
                || !response.path("expires_in").isIntegralNumber()
                || !response.path("expires_in").canConvertToLong()
                || response.path("expires_in").longValue() <= 0) {
            throw new IllegalStateException("Invalid service-token response");
        }
    }

    private static void requireStatus(ClientHttpResponse response, HttpStatus expected) throws IOException {
        if (response.getStatusCode().value() != expected.value()) {
            // Preserve status for the bounded 401 retry without buffering remote bodies or headers.
            throw new RestClientResponseException("Unexpected Risk admin HTTP status",
                    response.getStatusCode(), "", null, new byte[0], null);
        }
    }

    private synchronized void invalidate(String token) {
        if (token.equals(cachedToken)) {
            cachedToken = null;
            refreshAt = Instant.EPOCH;
        }
    }
}
