package com.zerotrust.risk.config;

import jakarta.validation.constraints.AssertTrue;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "risk.policy.network-risk.geoip")
@Getter
@Setter
public class GeoIpProperties {

    private boolean enabled;
    private String cityDatabasePath;
    private String asnDatabasePath;

    @AssertTrue(message = "geoip city database path is required when Geo-IP is enabled")
    public boolean isCityDatabaseConfiguredWhenEnabled() {
        return !enabled || hasText(cityDatabasePath);
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
