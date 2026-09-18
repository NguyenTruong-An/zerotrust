package com.zerotrust.risk.config;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Validated
@ConfigurationProperties(prefix = "risk.authentication-history")
@Getter
@Setter
public class AuthenticationHistoryProperties {

    @NotBlank
    @Size(min = 32)
    private String pepper;

    @NotBlank
    @Pattern(regexp = "[A-Za-z0-9][A-Za-z0-9:_-]{2,99}")
    private String keyPrefix;

    @NotNull
    private Duration failureWindow;

    @NotNull
    private Duration eventDeduplicationTtl;

    @AssertTrue(message = "failure window must be at least one second")
    public boolean isFailureWindowValid() {
        return isPositive(failureWindow);
    }

    @AssertTrue(message = "event deduplication TTL must cover the failure window")
    public boolean isEventDeduplicationTtlValid() {
        return eventDeduplicationTtl == null
                || failureWindow == null
                || isPositive(eventDeduplicationTtl)
                && eventDeduplicationTtl.compareTo(failureWindow) >= 0;
    }

    private static boolean isPositive(Duration duration) {
        return duration != null && duration.compareTo(Duration.ofSeconds(1)) >= 0;
    }
}
