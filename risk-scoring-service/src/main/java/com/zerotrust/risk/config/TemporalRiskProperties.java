package com.zerotrust.risk.config;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.math.BigDecimal;
import java.time.Duration;
import java.time.ZoneId;

@Validated
@ConfigurationProperties(prefix = "risk.policy.temporal-risk")
@Getter
@Setter
public class TemporalRiskProperties {

    @NotNull
    private Duration historyWindow;

    @Min(1)
    private int minimumEvents;

    @Min(1)
    @Max(10000)
    private int maximumEvents;

    @NotNull
    private ZoneId zoneId;

    @Min(0)
    @Max(12)
    private int hourTolerance;

    @NotNull
    @DecimalMin(value = "0.0", inclusive = false)
    @DecimalMax("1.0")
    private BigDecimal minimumDayFrequency;

    @NotNull
    @DecimalMin(value = "0.0", inclusive = false)
    @DecimalMax("1.0")
    private BigDecimal minimumHourFrequency;

    @NotNull
    @DecimalMin(value = "0.0", inclusive = false)
    @DecimalMax("100.0")
    private BigDecimal mediumScore;

    @NotNull
    @DecimalMin(value = "0.0", inclusive = false)
    @DecimalMax("100.0")
    private BigDecimal highScore;

    @AssertTrue(message = "temporal-risk history window must be positive")
    public boolean isHistoryWindowValid() {
        return historyWindow == null
                || (!historyWindow.isZero() && !historyWindow.isNegative());
    }

    @AssertTrue(message = "temporal-risk minimum events must not exceed maximum events")
    public boolean isEventRangeValid() {
        return minimumEvents <= maximumEvents;
    }

    @AssertTrue(message = "temporal-risk medium score must not exceed high score")
    public boolean isScoreOrderValid() {
        return mediumScore == null
                || highScore == null
                || mediumScore.compareTo(highScore) <= 0;
    }
}
