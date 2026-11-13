package com.zerotrust.risk.networkv2;

import java.time.Instant;

public record NetworkHistorySample(String subjectHash, String clientId, NetworkObservation observation,
                                   Instant authenticatedAt, Instant recordedAt) {}
