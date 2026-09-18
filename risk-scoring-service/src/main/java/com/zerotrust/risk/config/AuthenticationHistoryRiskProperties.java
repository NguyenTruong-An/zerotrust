package com.zerotrust.risk.config;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.math.BigDecimal;

@Validated
@ConfigurationProperties(prefix = "risk.policy.authentication-history-risk")
@Getter
@Setter
public class AuthenticationHistoryRiskProperties {

    @Min(1)
    private long subjectMediumMinimum;

    @Min(1)
    private long subjectHighMinimum;

    @Min(1)
    private long sourceIpMediumMinimum;

    @Min(1)
    private long sourceIpHighMinimum;

    @NotNull
    @DecimalMin(value = "0.0", inclusive = false)
    @DecimalMax("100.0")
    private BigDecimal mediumScore;

    @NotNull
    @DecimalMin(value = "0.0", inclusive = false)
    @DecimalMax("100.0")
    private BigDecimal highScore;

    @AssertTrue(message = "authentication-history medium thresholds must be lower than high thresholds")
    public boolean isThresholdOrderValid() {
        return subjectMediumMinimum < subjectHighMinimum
                && sourceIpMediumMinimum < sourceIpHighMinimum;
    }

    @AssertTrue(message = "authentication-history medium score must not exceed high score")
    public boolean isScoreOrderValid() {
        return mediumScore == null
                || highScore == null
                || mediumScore.compareTo(highScore) <= 0;
    }
}
