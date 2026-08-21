package com.zerotrust.zerotrust.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
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
        @DefaultValue("3s") Duration connectTimeout,
        @DefaultValue("5s") Duration readTimeout,
        @DefaultValue("10") @Min(1) int connectionPoolSize,
        @DefaultValue("30") @Min(0) long minTokenValiditySeconds
) {
}
