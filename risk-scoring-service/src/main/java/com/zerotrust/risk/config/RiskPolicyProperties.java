package com.zerotrust.risk.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

@Validated
@ConfigurationProperties(prefix = "risk.policy")
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

    public Weights getWeights() {
        return weights;
    }

    public void setWeights(Weights weights) {
        this.weights = weights;
    }

    public Thresholds getThresholds() {
        return thresholds;
    }

    public void setThresholds(Thresholds thresholds) {
        this.thresholds = thresholds;
    }

    public PriorityRules getPriorityRules() {
        return priorityRules;
    }

    public void setPriorityRules(PriorityRules priorityRules) {
        this.priorityRules = priorityRules;
    }

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

        public BigDecimal getDevice() {
            return device;
        }

        public void setDevice(BigDecimal device) {
            this.device = device;
        }

        public BigDecimal getNetwork() {
            return network;
        }

        public void setNetwork(BigDecimal network) {
            this.network = network;
        }

        public BigDecimal getTemporal() {
            return temporal;
        }

        public void setTemporal(BigDecimal temporal) {
            this.temporal = temporal;
        }

        public BigDecimal getAuthenticationHistory() {
            return authenticationHistory;
        }

        public void setAuthenticationHistory(BigDecimal authenticationHistory) {
            this.authenticationHistory = authenticationHistory;
        }

        private boolean isComplete() {
            return device != null
                    && network != null
                    && temporal != null
                    && authenticationHistory != null;
        }
    }

    public static class Thresholds {

        @NotNull
        @DecimalMin("0.0")
        @DecimalMax("100.0")
        private BigDecimal mediumMinimum;

        @NotNull
        @DecimalMin("0.0")
        @DecimalMax("100.0")
        private BigDecimal highMinimum;

        public BigDecimal getMediumMinimum() {
            return mediumMinimum;
        }

        public void setMediumMinimum(BigDecimal mediumMinimum) {
            this.mediumMinimum = mediumMinimum;
        }

        public BigDecimal getHighMinimum() {
            return highMinimum;
        }

        public void setHighMinimum(BigDecimal highMinimum) {
            this.highMinimum = highMinimum;
        }

        @AssertTrue(message = "medium threshold must be lower than high threshold")
        public boolean isOrderValid() {
            return mediumMinimum == null
                    || highMinimum == null
                    || mediumMinimum.compareTo(highMinimum) < 0;
        }
    }

    public static class PriorityRules {

        @NotNull
        private List<String> blockedIpAddresses = new ArrayList<>();

        public List<String> getBlockedIpAddresses() {
            return blockedIpAddresses;
        }

        public void setBlockedIpAddresses(List<String> blockedIpAddresses) {
            this.blockedIpAddresses = blockedIpAddresses;
        }
    }
}
