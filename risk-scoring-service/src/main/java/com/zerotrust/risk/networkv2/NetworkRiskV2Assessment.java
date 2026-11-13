package com.zerotrust.risk.networkv2;

import java.util.List;

public record NetworkRiskV2Assessment(Status status, Integer candidateScore,
        List<Contribution> contributions, List<String> reasons, int historySamples,
        int distinctDays, NetworkObservation.Quality quality, Integer cityAccuracyRadiusKm) {
    public enum Status { COMPLETE, PARTIAL, COLD_START, UNAVAILABLE, SKIPPED, ERROR }
    public record Contribution(String signal, Integer points, String evidence) {}
    public static NetworkRiskV2Assessment unavailable(Status status, String reason,
                                                     NetworkObservation.Quality quality) {
        return new NetworkRiskV2Assessment(status, null, List.of(), List.of(reason), 0, 0, quality, null);
    }
}
