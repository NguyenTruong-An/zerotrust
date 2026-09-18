package com.zerotrust.risk.service;

import com.zerotrust.risk.repository.AuthenticationFailureStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationFailureServiceTests {

    @Mock
    private AuthenticationFailureStore failureStore;

    private AuthenticationFailureService service;

    @BeforeEach
    void setUp() {
        service = new AuthenticationFailureService(failureStore);
    }

    @Test
    void normalizesEventAndAllowsUnknownSubject() {
        when(failureStore.recordFailure("event-1", null, "203.0.113.10"))
                .thenReturn(true);

        boolean recorded = service.recordFailure(" event-1 ", " ", " 203.0.113.10 ");

        assertThat(recorded).isTrue();
        verify(failureStore).recordFailure("event-1", null, "203.0.113.10");
    }

    @Test
    void readsSubjectAndIpCounters() {
        when(failureStore.countBySubject("subject-1")).thenReturn(2L);
        when(failureStore.countBySourceIp("203.0.113.10")).thenReturn(4L);

        assertThat(service.countForSubject(" subject-1 ")).isEqualTo(2L);
        assertThat(service.countForSourceIp(" 203.0.113.10 ")).isEqualTo(4L);
    }
}
