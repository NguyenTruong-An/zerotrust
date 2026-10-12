package com.zerotrust.keycloak.risk.client;

import com.zerotrust.keycloak.risk.config.RiskScoringClientConfig;
import com.zerotrust.keycloak.risk.config.ServiceTokenConfig;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectReader;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.math.BigDecimal;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class ClientCredentialsTokenProvider implements ServiceTokenProvider {

    private static final BoundedJsonResponseReader RESPONSE_READER = new BoundedJsonResponseReader(
            16 * 1024,
            "Token endpoint returned a non-JSON response",
            "Token endpoint response exceeds the size limit");
    private static final ObjectReader TOKEN_JSON_READER = JsonSerialization.mapper
            .readerFor(new TypeReference<Map<String, Object>>() {})
            .with(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);

    private final CloseableHttpClient httpClient;
    private final ServiceTokenConfig tokenConfig;
    private final RequestConfig requestConfig;
    private final ServiceTokenCache tokenCache;
    private final ServiceTokenCache.TokenCacheKey cacheKey;
    private final Clock clock;

    public ClientCredentialsTokenProvider(
            HttpClientProvider httpClientProvider,
            ServiceTokenConfig tokenConfig,
            RiskScoringClientConfig networkConfig,
            ServiceTokenCache tokenCache
    ) {
        this(
                Objects.requireNonNull(httpClientProvider, "httpClientProvider must not be null")
                        .getHttpClient(),
                tokenConfig,
                networkConfig,
                tokenCache,
                Clock.systemUTC()
        );
    }

    ClientCredentialsTokenProvider(
            CloseableHttpClient httpClient,
            ServiceTokenConfig tokenConfig,
            RiskScoringClientConfig networkConfig,
            ServiceTokenCache tokenCache,
            Clock clock
    ) {
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient must not be null");
        this.tokenConfig = Objects.requireNonNull(tokenConfig, "tokenConfig must not be null");
        Objects.requireNonNull(networkConfig, "networkConfig must not be null");
        this.tokenCache = Objects.requireNonNull(tokenCache, "tokenCache must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
        this.cacheKey = new ServiceTokenCache.TokenCacheKey(
                tokenConfig.tokenEndpointUri(),
                tokenConfig.clientId()
        );
        this.requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(RiskScoringClientConfig.timeoutMillis(
                        networkConfig.connectionRequestTimeout()))
                .setConnectTimeout(RiskScoringClientConfig.timeoutMillis(
                        networkConfig.connectTimeout()))
                .setSocketTimeout(RiskScoringClientConfig.timeoutMillis(
                        networkConfig.socketTimeout()))
                .setRedirectsEnabled(false)
                .build();
    }

    @Override
    public String accessToken() {
        return tokenCache.getOrLoad(
                cacheKey,
                clock.instant(),
                tokenConfig.refreshSkew(),
                this::requestToken
        ).accessToken();
    }

    @Override
    public void invalidate(String rejectedToken) {
        if (rejectedToken != null && !rejectedToken.isBlank()) {
            tokenCache.invalidate(cacheKey, rejectedToken);
        }
    }

    private ServiceTokenCache.CachedToken requestToken() {
        HttpPost request = new HttpPost(tokenConfig.tokenEndpointUri());
        request.setConfig(requestConfig);
        request.setHeader("Accept", "application/json");
        request.setHeader("Authorization", basicAuthorization());
        List<NameValuePair> form = List.of(new BasicNameValuePair(
                "grant_type",
                "client_credentials"
        ));
        request.setEntity(new UrlEncodedFormEntity(form, StandardCharsets.UTF_8));

        try (CloseableHttpResponse response = httpClient.execute(request)) {
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode < 200 || statusCode >= 300) {
                throw RiskScoringClientException.tokenEndpointStatus(statusCode);
            }
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                throw invalidTokenResponse("Token endpoint returned an empty response", null);
            }
            return parseToken(RESPONSE_READER.read(entity));
        } catch (RiskScoringClientException exception) {
            throw exception;
        } catch (InterruptedIOException exception) {
            if (Thread.currentThread().isInterrupted()) {
                throw RiskScoringClientException.interrupted(exception);
            }
            throw RiskScoringClientException.timeout(exception);
        } catch (IOException exception) {
            throw RiskScoringClientException.connection(exception);
        }
    }

    private String basicAuthorization() {
        String credentials = formEncode(tokenConfig.clientId())
                + ":" + formEncode(tokenConfig.clientSecret());
        String encoded = Base64.getEncoder().encodeToString(
                credentials.getBytes(StandardCharsets.UTF_8)
        );
        return "Basic " + encoded;
    }

    private static String formEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private ServiceTokenCache.CachedToken parseToken(String body) {
        try {
            Map<String, Object> values = TOKEN_JSON_READER.readValue(body);
            String accessToken = requiredString(values.get("access_token"), "access_token");
            String tokenType = requiredString(values.get("token_type"), "token_type");
            if (!"bearer".equalsIgnoreCase(tokenType)) {
                throw new IllegalArgumentException("token_type is not Bearer");
            }
            long expiresInSeconds = positiveLong(values.get("expires_in"), "expires_in");
            Instant expiresAt = clock.instant().plusSeconds(expiresInSeconds);
            return new ServiceTokenCache.CachedToken(accessToken, expiresAt);
        } catch (IOException | RuntimeException exception) {
            // Parser exceptions can contain credential-bearing response excerpts.
            throw invalidTokenResponse("Token endpoint returned an invalid token response", null);
        }
    }

    private static String requiredString(Object value, String fieldName) {
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must be a non-empty string");
        }
        return text;
    }

    private static long positiveLong(Object value, String fieldName) {
        if (!(value instanceof Number number)) {
            throw new IllegalArgumentException(fieldName + " must be a number");
        }
        long result = new BigDecimal(number.toString()).longValueExact();
        if (result <= 0) {
            throw new IllegalArgumentException(fieldName + " must be positive");
        }
        return result;
    }

    private static RiskScoringClientException invalidTokenResponse(
            String message,
            Throwable cause
    ) {
        return RiskScoringClientException.invalidResponse(message, cause);
    }
}
