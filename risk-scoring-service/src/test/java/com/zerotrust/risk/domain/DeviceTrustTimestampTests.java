package com.zerotrust.risk.domain;

import com.zerotrust.risk.entity.KnownDeviceEntity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import java.time.Instant;
import static org.assertj.core.api.Assertions.*;

class DeviceTrustTimestampTests {
    @ParameterizedTest
    @CsvSource({"0,0","1,0","499,0","500,1000","501,1000","999,1000","1000,1000",
            "123456000,123456000","123456001,123456000","123456499,123456000","123456500,123457000",
            "123456501,123457000","123456789,123457000","123456999,123457000",
            "999999499,999999000","999999500,1000000000","999999999,1000000000"})
    void independentMicrosecondBoundaryExpectations(long input,long expected) {
        var start=Instant.parse("2026-10-15T00:00:00Z");
        assertThat(DeviceTrustTimestamp.canonical(start.plusNanos(input))).isEqualTo(start.plusNanos(expected));
    }
    @Test void canonicalizationIsMonotoneAndIdempotentAcrossSecondBoundary() {
        var start=Instant.parse("2026-10-15T00:00:00.999998Z");var previous=DeviceTrustTimestamp.canonical(start);
        for(int n=0;n<4000;n++) {
            var value=DeviceTrustTimestamp.canonical(start.plusNanos(n));
            assertThat(value).isAfterOrEqualTo(previous);assertThat(value.getNano()%1000).isZero();
            assertThat(DeviceTrustTimestamp.canonical(value)).isEqualTo(value);previous=value;
        }
    }
    @Test void negativeEpochCarryUsesInstantNormalizationWithoutMillisArithmetic() {
        assertThat(DeviceTrustTimestamp.canonical(Instant.parse("1969-12-31T23:59:59.999999500Z"))).isEqualTo(Instant.EPOCH);
    }
    @Test void invalidInputAndUnrepresentableCarryFailWithoutClamping() {
        assertThatNullPointerException().isThrownBy(()->DeviceTrustTimestamp.canonical(null));
        assertThatThrownBy(()->DeviceTrustTimestamp.canonical(Instant.MAX)).isInstanceOf(java.time.DateTimeException.class);
    }
    @Test void allEntityLifecycleFieldsUseTheSameCanonicalPrecision() {
        var input=Instant.parse("2026-10-15T00:00:00.123456789Z");var canonical=Instant.parse("2026-10-15T00:00:00.123457Z");
        var d=new KnownDeviceEntity("Alice","a".repeat(64),input);d.trust(input);d.markSeen(input);d.revoke(input);
        assertThat(d.getFirstSeenAt()).isEqualTo(canonical);assertThat(d.getTrustedAt()).isEqualTo(canonical);
        assertThat(d.getLastSeenAt()).isEqualTo(canonical);assertThat(d.getRevokedAt()).isEqualTo(canonical);
    }
    @Test void canonicalBackwardChronologyStillRejectsWithoutStateMutation() {
        var first=Instant.parse("2026-10-15T00:00:00.123456789Z");var d=new KnownDeviceEntity("Alice","a".repeat(64),first);d.trust(first);
        assertThatThrownBy(()->d.revoke(first.minusNanos(2000))).hasMessage("revokedAt must not be before firstSeenAt");
        assertThat(d.getRevokedAt()).isNull();assertThat(d.getStatus()).isEqualTo(com.zerotrust.risk.entity.DeviceStatus.TRUSTED);
    }
}
