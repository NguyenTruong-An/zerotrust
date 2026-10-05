package com.zerotrust.risk.service;

import com.zerotrust.risk.config.AuthenticationHistoryProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

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
                .isNotEqualTo(hasher.hash("event", "user-123"));
    }

    @ParameterizedTest
    @CsvSource({
            "2001:db8::1, 2001:db8:0:0:0:0:0:1",
            "2001:0DB8::ABCD, 2001:db8:0:0:0:0:0:abcd",
            "2001:db8::192.0.2.1, 2001:db8:0:0:0:0:c000:201",
            "203.0.113.10, 203.000.113.010"
    })
    void usesTheSameCounterKeyForEquivalentIpRepresentations(String first, String second) {
        assertThat(hasher.hash("ip", first)).isEqualTo(hasher.hash("ip", second));
    }

    @Test
    void keepsDifferentAddressesAndNonIpScopesDistinct() {
        assertThat(hasher.hash("ip", "2001:db8::1"))
                .isNotEqualTo(hasher.hash("ip", "2001:db8::2"));
        assertThat(hasher.hash("subject", "2001:db8::1"))
                .isNotEqualTo(hasher.hash("subject", "2001:db8:0:0:0:0:0:1"));
        assertThat(hasher.hash("ip", "203.0.113.10"))
                .isNotEqualTo(hasher.hash("subject", "203.0.113.10"));
    }

    @Test
    void rejectsHostnamesForIpCounterKeys() {
        assertThatThrownBy(() -> hasher.hash("ip", "example.invalid"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsBlankScopeOrValue() {
        assertThatThrownBy(() -> hasher.hash(" ", "value"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> hasher.hash("subject", " "))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
