package com.zerotrust.risk.config;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "risk.network-v2")
public class NetworkRiskV2Properties {
    // Intentionally no enforcement mode. This experiment cannot select a live decision.
    public enum Mode { DISABLED, SHADOW }

    @NotNull private Mode mode = Mode.DISABLED;
    @NotBlank private String monitoredClientId = "zerotrust-spa";
    @Min(1) @Max(90) private int historyDays = 30;
    @Min(3) @Max(1000) private int historyLimit = 128;
    @Min(3) @Max(100) private int minimumSamples = 3;
    @Min(2) @Max(30) private int minimumDistinctDays = 2;
    @Min(1) @Max(10000) private int pendingCapacity = 4096;
    @Min(1) @Max(1024) private int workQueueCapacity = 128;
    @NotNull private Duration pendingTtl = Duration.ofMinutes(10);
    private boolean retentionEnabled = false;
    @Min(1) @Max(90) private int retentionDays = 30;
    @Min(1) @Max(1000) private int retentionBatchSize = 200;
    @NotNull private Duration retentionInterval = Duration.ofHours(1);

    public boolean isShadow() { return mode == Mode.SHADOW; }

    @AssertTrue(message = "network-v2 history and pending bounds are inconsistent")
    public boolean isBounded() {
        return minimumSamples <= historyLimit && minimumDistinctDays <= historyDays
                && retentionDays >= historyDays && (!retentionEnabled || isShadow())
                && retentionInterval != null && retentionInterval.compareTo(Duration.ofMinutes(5)) >= 0
                && retentionInterval.compareTo(Duration.ofDays(1)) <= 0
                && pendingTtl != null && pendingTtl.compareTo(Duration.ofSeconds(1)) >= 0
                && pendingTtl.compareTo(Duration.ofMinutes(30)) <= 0;
    }
}
