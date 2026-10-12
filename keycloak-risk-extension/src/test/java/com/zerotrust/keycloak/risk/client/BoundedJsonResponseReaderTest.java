package com.zerotrust.keycloak.risk.client;

import org.apache.http.entity.BasicHttpEntity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BoundedJsonResponseReaderTest {
    private final BoundedJsonResponseReader reader = new BoundedJsonResponseReader(
            8, "non-JSON response", "response too large");

    @ParameterizedTest
    @ValueSource(longs = {8, -1})
    void acceptsExactByteLimitAndClosesStream(long contentLength) throws IOException {
        TrackingStream stream = new TrackingStream("12345678");

        assertEquals("12345678", reader.read(entity(stream, contentLength, "application/json")));
        assertTrue(stream.closed);
    }

    @ParameterizedTest
    @ValueSource(longs = {-1, 4})
    void rejectsOversizedBodyEvenWithoutReliableContentLength(long contentLength) {
        TrackingStream stream = new TrackingStream("123456789");

        RiskScoringClientException exception = assertThrows(RiskScoringClientException.class,
                () -> reader.read(entity(stream, contentLength, "application/json")));

        assertEquals(RiskScoringClientException.FailureType.INVALID_RESPONSE, exception.failureType());
        assertEquals("response too large", exception.getMessage());
        assertTrue(stream.closed);
    }

    @Test
    void limitsUtf8BytesRatherThanCharacters() {
        TrackingStream stream = new TrackingStream("\"éééé\"");

        assertThrows(RiskScoringClientException.class,
                () -> reader.read(entity(stream, -1, "application/json")));
        assertTrue(stream.closed);
    }

    @ParameterizedTest
    @CsvSource({"application/json, true", "APPLICATION/JSON; charset=UTF-8, true",
            "application/problem+json, true", "text/html, false"})
    void recognizesJsonContentTypes(String contentType, boolean accepted) throws IOException {
        BasicHttpEntity entity = entity(new TrackingStream("{}"), 2, contentType);
        if (accepted) {
            assertEquals("{}", reader.read(entity));
        } else {
            RiskScoringClientException exception = assertThrows(RiskScoringClientException.class,
                    () -> reader.read(entity));
            assertEquals("non-JSON response", exception.getMessage());
        }
    }

    @Test
    void rejectsMissingContentType() {
        assertThrows(RiskScoringClientException.class,
                () -> reader.read(entity(new TrackingStream("{}"), 2, null)));
    }

    private BasicHttpEntity entity(TrackingStream stream, long length, String contentType) {
        BasicHttpEntity entity = new BasicHttpEntity();
        entity.setContent(stream);
        entity.setContentLength(length);
        entity.setContentType(contentType);
        return entity;
    }

    private static final class TrackingStream extends ByteArrayInputStream {
        private boolean closed;

        private TrackingStream(String body) {
            super(body.getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public void close() throws IOException {
            closed = true;
            super.close();
        }
    }
}
