package com.zerotrust.risk.service;

import com.zerotrust.risk.config.AuthenticationHistoryProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthenticationHistoryKeyHasherTests {

    private AuthenticationHistoryKeyHasher hasher;

    @BeforeEach
    void setUp() {
        AuthenticationHistoryProperties properties = new AuthenticationHistoryProperties();
        properties.setPepper("test-only-authentication-history-pepper-value");
        hasher = new AuthenticationHistoryKeyHasher(properties);
    }

    @Test
    void createsStableScopedHmacWithoutExposingInput() {
        String subjectHash = hasher.hash("subject", "user-123");

        assertThat(subjectHash)
                .hasSize(64)
                .matches("[0-9a-f]{64}")
                .doesNotContain("user-123")
                .isEqualTo(hasher.hash("subject", "user-123"))
                .isNotEqualTo(hasher.hash("ip", "user-123"));
    }

    @Test
    void rejectsBlankScopeOrValue() {
        assertThatThrownBy(() -> hasher.hash(" ", "value"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> hasher.hash("subject", " "))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
