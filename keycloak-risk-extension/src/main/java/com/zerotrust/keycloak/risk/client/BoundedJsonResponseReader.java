package com.zerotrust.keycloak.risk.client;

import org.apache.http.Header;
import org.apache.http.HttpEntity;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Objects;

/** Reads JSON responses without trusting Content-Length as the only size guard. */
final class BoundedJsonResponseReader {
    private static final int BUFFER_SIZE = 8 * 1024;

    private final int maxBytes;
    private final String nonJsonMessage;
    private final String sizeLimitMessage;

    BoundedJsonResponseReader(int maxBytes, String nonJsonMessage, String sizeLimitMessage) {
        if (maxBytes <= 0) {
            throw new IllegalArgumentException("maxBytes must be positive");
        }
        this.maxBytes = maxBytes;
        this.nonJsonMessage = Objects.requireNonNull(nonJsonMessage);
        this.sizeLimitMessage = Objects.requireNonNull(sizeLimitMessage);
    }

    String read(HttpEntity entity) throws IOException {
        verifyJsonContentType(entity);
        long contentLength = entity.getContentLength();
        if (contentLength > maxBytes) {
            throw responseTooLarge();
        }

        int initialCapacity = contentLength <= 0
                ? Math.min(BUFFER_SIZE, maxBytes)
                : (int) Math.min(contentLength, maxBytes);
        try (InputStream input = entity.getContent();
             ByteArrayOutputStream output = new ByteArrayOutputStream(initialCapacity)) {
            byte[] buffer = new byte[Math.min(BUFFER_SIZE, maxBytes)];
            int totalBytes = 0;
            int bytesRead;
            while ((bytesRead = input.read(buffer)) != -1) {
                if (bytesRead > maxBytes - totalBytes) {
                    throw responseTooLarge();
                }
                output.write(buffer, 0, bytesRead);
                totalBytes += bytesRead;
            }
            return output.toString(StandardCharsets.UTF_8);
        }
    }

    private void verifyJsonContentType(HttpEntity entity) {
        Header header = entity.getContentType();
        String value = header == null ? "" : header.getValue().toLowerCase(Locale.ROOT);
        int parametersStart = value.indexOf(';');
        String mediaType = parametersStart >= 0
                ? value.substring(0, parametersStart).trim()
                : value.trim();
        if (!("application/json".equals(mediaType) || mediaType.endsWith("+json"))) {
            throw RiskScoringClientException.invalidResponse(nonJsonMessage, null);
        }
    }

    private RiskScoringClientException responseTooLarge() {
        return RiskScoringClientException.invalidResponse(sizeLimitMessage, null);
    }
}
