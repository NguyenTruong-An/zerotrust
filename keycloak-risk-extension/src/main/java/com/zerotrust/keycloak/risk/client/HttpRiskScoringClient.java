package com.zerotrust.keycloak.risk.client;

import com.zerotrust.keycloak.risk.config.RiskScoringClientConfig;
import com.zerotrust.keycloak.risk.dto.RiskEvaluationRequest;
import com.zerotrust.keycloak.risk.dto.RiskEvaluationResponse;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.util.JsonSerialization;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Objects;

public final class HttpRiskScoringClient implements RiskScoringClient {

    private static final int BUFFER_SIZE = 8 * 1024;
    private static final ContentType JSON_UTF_8 = ContentType.create(
            "application/json",
            StandardCharsets.UTF_8
    );

    private final CloseableHttpClient httpClient;
    private final URI evaluationUri;
    private final RequestConfig requestConfig;
    private final int maxResponseBytes;

    public HttpRiskScoringClient(
            HttpClientProvider httpClientProvider,
            RiskScoringClientConfig config
    ) {
        this(
                Objects.requireNonNull(httpClientProvider, "httpClientProvider must not be null")
                        .getHttpClient(),
                config
        );
    }

    HttpRiskScoringClient(CloseableHttpClient httpClient, RiskScoringClientConfig config) {
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient must not be null");
        Objects.requireNonNull(config, "config must not be null");
        this.evaluationUri = config.evaluationUri();
        this.requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(RiskScoringClientConfig.timeoutMillis(
                        config.connectionRequestTimeout()))
                .setConnectTimeout(RiskScoringClientConfig.timeoutMillis(config.connectTimeout()))
                .setSocketTimeout(RiskScoringClientConfig.timeoutMillis(config.socketTimeout()))
                .setRedirectsEnabled(false)
                .build();
        this.maxResponseBytes = config.maxResponseBytes();
    }

    @Override
    public RiskEvaluationResponse evaluate(RiskEvaluationRequest request) {
        Objects.requireNonNull(request, "request must not be null");

        HttpPost httpRequest = new HttpPost(evaluationUri);
        httpRequest.setConfig(requestConfig);
        httpRequest.setHeader("Accept", "application/json");
        httpRequest.setEntity(new StringEntity(
                serialize(request),
                JSON_UTF_8
        ));

        try (CloseableHttpResponse httpResponse = httpClient.execute(httpRequest)) {
            int statusCode = httpResponse.getStatusLine().getStatusCode();
            if (statusCode < 200 || statusCode >= 300) {
                throw RiskScoringClientException.httpStatus(statusCode);
            }

            HttpEntity responseEntity = httpResponse.getEntity();
            if (responseEntity == null) {
                throw RiskScoringClientException.invalidResponse(
                        "Risk Scoring Service returned an empty response",
                        null
                );
            }
            verifyJsonContentType(responseEntity);

            RiskEvaluationResponse response = deserialize(readResponseBody(responseEntity));
            verifyCorrelation(request, response);
            return response;
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

    private static String serialize(RiskEvaluationRequest request) {
        try {
            return JsonSerialization.writeValueAsString(request);
        } catch (IOException | RuntimeException exception) {
            throw RiskScoringClientException.serialization(exception);
        }
    }

    private static void verifyJsonContentType(HttpEntity responseEntity) {
        Header contentTypeHeader = responseEntity.getContentType();
        String contentType = contentTypeHeader == null
                ? ""
                : contentTypeHeader.getValue().toLowerCase(Locale.ROOT);
        int parametersStart = contentType.indexOf(';');
        String mediaType = parametersStart >= 0
                ? contentType.substring(0, parametersStart).trim()
                : contentType.trim();

        if (!("application/json".equals(mediaType) || mediaType.endsWith("+json"))) {
            throw RiskScoringClientException.invalidResponse(
                    "Risk Scoring Service returned a non-JSON response",
                    null
            );
        }
    }

    private String readResponseBody(HttpEntity responseEntity) {
        long contentLength = responseEntity.getContentLength();
        if (contentLength > maxResponseBytes) {
            throw responseTooLarge();
        }

        try (InputStream input = responseEntity.getContent();
             ByteArrayOutputStream output = new ByteArrayOutputStream(
                     initialBufferCapacity(contentLength))) {
            byte[] buffer = new byte[BUFFER_SIZE];
            int totalBytes = 0;
            int bytesRead;
            while ((bytesRead = input.read(buffer)) != -1) {
                if (bytesRead > maxResponseBytes - totalBytes) {
                    throw responseTooLarge();
                }
                output.write(buffer, 0, bytesRead);
                totalBytes += bytesRead;
            }
            return output.toString(StandardCharsets.UTF_8);
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

    private int initialBufferCapacity(long contentLength) {
        if (contentLength <= 0) {
            return Math.min(BUFFER_SIZE, maxResponseBytes);
        }
        return (int) Math.min(contentLength, maxResponseBytes);
    }

    private static RiskScoringClientException responseTooLarge() {
        return RiskScoringClientException.invalidResponse(
                "Risk Scoring Service response exceeds the configured size limit",
                null
        );
    }

    private static RiskEvaluationResponse deserialize(String responseBody) {
        try {
            return JsonSerialization.readValue(responseBody, RiskEvaluationResponse.class);
        } catch (IOException | RuntimeException exception) {
            throw RiskScoringClientException.invalidResponse(
                    "Risk Scoring Service returned invalid JSON",
                    exception
            );
        }
    }

    private static void verifyCorrelation(
            RiskEvaluationRequest request,
            RiskEvaluationResponse response
    ) {
        if (!request.subjectId().equals(response.subjectId())
                || !request.authenticationSessionId().equals(response.authenticationSessionId())) {
            throw RiskScoringClientException.invalidResponse(
                    "Risk response does not match the authentication request",
                    null
            );
        }
    }
}
