package com.zerotrust.risk.service;

import com.zerotrust.risk.config.DeviceFingerprintProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DeviceFingerprintHasherTests {

    private DeviceFingerprintHasher hasher;

    @BeforeEach
    void setUp() {
        DeviceFingerprintProperties properties = new DeviceFingerprintProperties();
        properties.setPepper("test-only-device-fingerprint-pepper-value");
        hasher = new DeviceFingerprintHasher(properties);
    }

    @Test
    void producesDeterministicLowercaseSha256Hex() {
        String first = hasher.hash("subject-1", "device-1");
        String second = hasher.hash("subject-1", "device-1");

        assertThat(first)
                .isEqualTo(second)
                .hasSize(64)
                .matches("[0-9a-f]{64}");
    }

    @Test
    void scopesTheSameDeviceToEachSubject() {
        String firstSubject = hasher.hash("subject-1", "shared-device-id");
        String secondSubject = hasher.hash("subject-2", "shared-device-id");

        assertThat(firstSubject).isNotEqualTo(secondSubject);
    }

    @Test
    void rejectsBlankInput() {
        assertThatThrownBy(() -> hasher.hash("subject-1", " "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("deviceId");
    }
}
