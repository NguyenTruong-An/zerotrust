package com.zerotrust.risk.domain;

import com.zerotrust.risk.config.DeviceFingerprintProperties;
import com.zerotrust.risk.service.DeviceFingerprintHasher;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import java.time.Instant;
import static org.assertj.core.api.Assertions.*;

class SubjectIdentifierNormalizerTests {
    @ParameterizedTest
    @ValueSource(strings={"550e8400-e29b-41d4-a716-446655440000", "550E8400-E29B-41D4-A716-446655440000",
            "not-a-uuid", "f:component:external-id", "opaque-Café", "\u00a0opaque\u00a0"})
    void acceptedOpaqueTextAndCaseArePreserved(String canonical) {
        assertThat(SubjectIdentifierNormalizer.normalize(" \t"+canonical+"\r\n")).isEqualTo(canonical);
        assertThat(new LoginContext(" "+canonical+" ","session","client","192.0.2.1",null,"device",Instant.EPOCH).subjectId())
                .isEqualTo(canonical);
    }
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings={" ","\t\r\n","\u2003"})
    void absentIdentityIsRejected(String subject) {
        assertThatThrownBy(()->SubjectIdentifierNormalizer.normalize(subject)).isInstanceOf(RuntimeException.class);
        assertThatThrownBy(()->new LoginContext(subject,"session","client","192.0.2.1",null,null,Instant.EPOCH))
                .isInstanceOf(RuntimeException.class);
    }
    @Test void lengthUsesTheExistingRequestLimitBeforeTrimming() {
        assertThat(SubjectIdentifierNormalizer.normalize("x".repeat(255))).hasSize(255);
        assertThatThrownBy(()->SubjectIdentifierNormalizer.normalize("x".repeat(256))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->SubjectIdentifierNormalizer.normalize(" "+"x".repeat(255))).isInstanceOf(IllegalArgumentException.class);
    }
    @Test void distinctOpaqueIdentitiesAreNotCaseFoldedOrUnicodeNormalized() {
        assertThat(SubjectIdentifierNormalizer.normalize(" user-A ")).isNotEqualTo(SubjectIdentifierNormalizer.normalize("user-a"));
        assertThat(SubjectIdentifierNormalizer.normalize("café")).isNotEqualTo(SubjectIdentifierNormalizer.normalize("cafe\u0301"));
    }
    @Test void existingHmacFormatKeepsAnIndependentFixedVectorAndSubjectScope() {
        var properties=new DeviceFingerprintProperties();properties.setPepper("qa-fix04-only-synthetic-device-pepper");
        var hasher=new DeviceFingerprintHasher(properties);
        // Independently calculated with .NET HMACSHA256 over UTF-8 subject + NUL + device.
        String expected="9d911ce6e0b374157f0aecd078a11abd73abdd503ab47022c93dbb67c72199a4";
        assertThat(hasher.hash("550e8400-e29b-41d4-a716-446655440000","device")).isEqualTo(expected);
        assertThat(hasher.hash(" 550e8400-e29b-41d4-a716-446655440000 ","device")).isEqualTo(expected);
        assertThat(hasher.hash("550E8400-E29B-41D4-A716-446655440000","device")).isNotEqualTo(expected);
        assertThat(hasher.hash("550e8400-e29b-41d4-a716-446655440001","device")).isNotEqualTo(expected);
    }
}
