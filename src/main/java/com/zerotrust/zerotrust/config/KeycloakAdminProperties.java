package com.zerotrust.zerotrust.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.hibernate.validator.constraints.time.DurationMax;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Validated
@ConfigurationProperties(prefix = "keycloak.admin")
public record KeycloakAdminProperties(
        @NotBlank String serverUrl,
        @NotBlank String realm,
        @NotBlank String clientId,
        @NotBlank String clientSecret,
        @DefaultValue("3s") @NotNull
        @DurationMin(millis = 1, message = "must be at least 1 millisecond")
        @DurationMax(millis = Integer.MAX_VALUE, message = "must not exceed 2147483647 milliseconds")
        Duration connectTimeout,
        @DefaultValue("5s") @NotNull
        @DurationMin(millis = 1, message = "must be at least 1 millisecond")
        @DurationMax(millis = Integer.MAX_VALUE, message = "must not exceed 2147483647 milliseconds")
        Duration readTimeout,
        @DefaultValue("3s") @NotNull
        @DurationMin(millis = 1, message = "must be at least 1 millisecond")
        @DurationMax(millis = Integer.MAX_VALUE, message = "must not exceed 2147483647 milliseconds")
        Duration connectionCheckoutTimeout,
        @DefaultValue("10") @Min(1) int connectionPoolSize,
        @DefaultValue("30") @Min(0) long minTokenValiditySeconds
) {
    @Override
    public String toString() {
        return "KeycloakAdminProperties[clientId=" + clientId + ", realm=" + realm + ", clientSecret=[redacted]]";
    }
}
