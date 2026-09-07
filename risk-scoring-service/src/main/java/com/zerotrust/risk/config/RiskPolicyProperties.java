package com.zerotrust.risk.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

@Validated
@ConfigurationProperties(prefix = "risk.policy")
@Getter
@Setter
public class RiskPolicyProperties {

    @Valid
    @NotNull
    private Weights weights = new Weights();

    @Valid
    @NotNull
    private Thresholds thresholds = new Thresholds();

    @Valid
    @NotNull
    private PriorityRules priorityRules = new PriorityRules();

    @AssertTrue(message = "risk policy weights must add up to 1.0")
    public boolean isWeightSumValid() {
        if (weights == null || !weights.isComplete()) {
            return true;
        }

        return weights.device
                .add(weights.network)
                .add(weights.temporal)
                .add(weights.authenticationHistory)
                .compareTo(BigDecimal.ONE) == 0;
    }

    @Getter
    @Setter
    public static class Weights {

        @NotNull
        @DecimalMin("0.0")
        @DecimalMax("1.0")
        private BigDecimal device;

        @NotNull
        @DecimalMin("0.0")
        @DecimalMax("1.0")
        private BigDecimal network;

        @NotNull
        @DecimalMin("0.0")
        @DecimalMax("1.0")
        private BigDecimal temporal;

        @NotNull
        @DecimalMin("0.0")
        @DecimalMax("1.0")
        private BigDecimal authenticationHistory;

        private boolean isComplete() {
            return device != null
                    && network != null
                    && temporal != null
                    && authenticationHistory != null;
        }
    }

    @Getter
    @Setter
    public static class Thresholds {

        @NotNull
        @DecimalMin("0.0")
        @DecimalMax("100.0")
        private BigDecimal mediumMinimum;

        @NotNull
        @DecimalMin("0.0")
        @DecimalMax("100.0")
        private BigDecimal highMinimum;

        @AssertTrue(message = "medium threshold must be lower than high threshold")
        public boolean isOrderValid() {
            return mediumMinimum == null
                    || highMinimum == null
                    || mediumMinimum.compareTo(highMinimum) < 0;
        }
    }

    @Getter
    @Setter
    public static class PriorityRules {

        @NotNull
        private List<String> blockedIpAddresses = new ArrayList<>();

    }
}
