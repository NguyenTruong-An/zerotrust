package com.zerotrust.risk.domain;

import java.time.Instant;
import java.util.Objects;

/**
 * Canonical device lifecycle time: nearest microsecond, half toward the next microsecond.
 * Matches the verified TIMESTAMP(6) JDBC rounding, including carry into the next second.
 * Exact microseconds also round-trip unchanged with truncating storage sessions.
 * Ordering remains strict between canonical instants; this is not a backward-clock clamp.
 */
public final class DeviceTrustTimestamp {
    private DeviceTrustTimestamp() { }

    public static Instant canonical(Instant timestamp) {
        Objects.requireNonNull(timestamp, "timestamp must not be null");
        long nanos = ((timestamp.getNano() + 500L) / 1_000L) * 1_000L;
        return Instant.ofEpochSecond(timestamp.getEpochSecond(), nanos);
    }
}
