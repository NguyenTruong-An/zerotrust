package com.zerotrust.risk.config;

import com.zerotrust.risk.service.GeoIpProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

@Component("geoIp")
@RequiredArgsConstructor
public class GeoIpHealthIndicator implements HealthIndicator {

    private final GeoIpProvider geoIpProvider;

    @Override
    public Health health() {
        if (!geoIpProvider.isEnabled()) {
            return Health.up()
                    .withDetail("enabled", false)
                    .build();
        }
        if (geoIpProvider.isReady()) {
            return Health.up()
                    .withDetail("enabled", true)
                    .withDetail("database", "ready")
                    .build();
        }
        return Health.down()
                .withDetail("enabled", true)
                .withDetail("database", "unavailable")
                .build();
    }
}
