package com.zerotrust.zerotrust.identity.keycloak;

import com.zerotrust.zerotrust.exception.ErrorCode;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KeycloakExceptionMapperTest {

    @Mock
    private Response response;

    private final KeycloakExceptionMapper mapper = new KeycloakExceptionMapper();

    @ParameterizedTest
    @CsvSource(value = {
            "User exists with same email|EMAIL_EXISTS",
            "User exists with same username|USERNAME_EXISTS",
            "Unknown conflict|INVALID_REQUEST"
    }, delimiter = '|')
    void mapsSmallConflictBodiesAndClosesTheEntityStream(String body, ErrorCode expected) {
        TrackingInputStream stream = conflictBody(body);

        assertThat(mapper.mapCreateFailure(response).getErrorCode()).isEqualTo(expected);
        assertThat(stream.closed).isTrue();
    }

    @Test
    void stopsReadingAnOversizedBodyAndUsesTheGenericConflict() {
        TrackingInputStream stream = conflictBody("email " + "x".repeat(1024 * 1024));

        assertThat(mapper.mapCreateFailure(response).getErrorCode()).isEqualTo(ErrorCode.INVALID_REQUEST);
        assertThat(stream.bytesRead).isLessThanOrEqualTo(8193);
        assertThat(stream.closed).isTrue();
    }

    @Test
    void acceptsAConflictBodyExactlyAtTheSizeLimit() {
        TrackingInputStream stream = conflictBody("x".repeat(8192 - 5) + "email");

        assertThat(mapper.mapCreateFailure(response).getErrorCode()).isEqualTo(ErrorCode.EMAIL_EXISTS);
        assertThat(stream.bytesRead).isEqualTo(8192);
        assertThat(stream.closed).isTrue();
    }

    @Test
    void unreadableConflictBodyStillMapsToAGenericConflictAndClosesTheStream() throws IOException {
        when(response.getStatus()).thenReturn(Response.Status.CONFLICT.getStatusCode());
        when(response.hasEntity()).thenReturn(true);
        InputStream stream = mock(InputStream.class);
        when(response.readEntity(InputStream.class)).thenReturn(stream);
        when(stream.readNBytes(anyInt())).thenThrow(new IOException("body read failed"));

        assertThat(mapper.mapCreateFailure(response).getErrorCode()).isEqualTo(ErrorCode.INVALID_REQUEST);
        verify(stream).close();
    }

    @Test
    void missingConflictBodyUsesTheGenericConflict() {
        when(response.getStatus()).thenReturn(Response.Status.CONFLICT.getStatusCode());

        assertThat(mapper.mapCreateFailure(response).getErrorCode()).isEqualTo(ErrorCode.INVALID_REQUEST);
    }

    @SuppressWarnings("unchecked")
    private TrackingInputStream conflictBody(String body) {
        when(response.getStatus()).thenReturn(Response.Status.CONFLICT.getStatusCode());
        when(response.hasEntity()).thenReturn(true);
        TrackingInputStream stream = new TrackingInputStream(body.getBytes(StandardCharsets.UTF_8));
        when(response.readEntity(any(Class.class))).thenAnswer(invocation -> {
            Class<?> requestedType = invocation.getArgument(0);
            return requestedType == InputStream.class
                    ? stream
                    : new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        });
        return stream;
    }

    private static final class TrackingInputStream extends InputStream {
        private final ByteArrayInputStream delegate;
        private int bytesRead;
        private boolean closed;

        private TrackingInputStream(byte[] bytes) {
            delegate = new ByteArrayInputStream(bytes);
        }

        @Override
        public int read() {
            int value = delegate.read();
            if (value >= 0) {
                bytesRead++;
            }
            return value;
        }

        @Override
        public int read(byte[] bytes, int offset, int length) {
            int read = delegate.read(bytes, offset, length);
            if (read > 0) {
                bytesRead += read;
            }
            return read;
        }

        @Override
        public void close() throws IOException {
            closed = true;
            delegate.close();
        }
    }
}
