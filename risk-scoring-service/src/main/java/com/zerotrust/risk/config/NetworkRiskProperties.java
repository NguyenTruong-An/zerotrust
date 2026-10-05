package com.zerotrust.risk.config;

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
import java.util.Locale;

@Validated
@ConfigurationProperties(prefix = "risk.policy.network-risk")
@Getter
@Setter
public class NetworkRiskProperties {

    private boolean enabled;

    @NotNull
    @DecimalMin("0.0")
    @DecimalMax("100.0")
    private BigDecimal defaultScore;

    @NotNull
    @DecimalMin(value = "0.0", inclusive = false)
    @DecimalMax("100.0")
    private BigDecimal elevatedScore;

    @NotNull
    @DecimalMin(value = "0.0", inclusive = false)
    @DecimalMax("100.0")
    private BigDecimal highScore;

    @NotNull
    private List<String> trustedCidrs = new ArrayList<>();

    @NotNull
    private List<String> elevatedRiskCidrs = new ArrayList<>();

    @NotNull
    private List<String> highRiskCidrs = new ArrayList<>();

    @NotNull
    private List<String> trustedCountryCodes = new ArrayList<>();

    @NotNull
    private List<String> elevatedRiskCountryCodes = new ArrayList<>();

    @NotNull
    private List<String> highRiskCountryCodes = new ArrayList<>();

    @AssertTrue(message = "network-risk elevated score must not exceed high score")
    public boolean isScoreOrderValid() {
        return elevatedScore == null
                || highScore == null
                || elevatedScore.compareTo(highScore) <= 0;
    }

    @AssertTrue(message = "network-risk default score must not exceed elevated score")
    public boolean isDefaultScoreOrderValid() {
        return defaultScore == null
                || elevatedScore == null
                || defaultScore.compareTo(elevatedScore) <= 0;
    }

    @AssertTrue(message = "network-risk country codes must use ISO 3166-1 alpha-2 format")
    public boolean isCountryCodeFormatValid() {
        return validCountryCodes(trustedCountryCodes)
                && validCountryCodes(elevatedRiskCountryCodes)
                && validCountryCodes(highRiskCountryCodes);
    }

    private static boolean validCountryCodes(List<String> values) {
        return values != null && values.stream().allMatch(value -> {
            if (value == null) {
                return false;
            }
            String normalized = value.trim().toUpperCase(Locale.ROOT);
            return normalized.matches("[A-Z]{2}");
        });
    }
}
