package com.zerotrust.risk.config;

import com.zerotrust.risk.service.GeoIpProvider;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Status;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GeoIpHealthIndicatorTests {

    @Test
    void disabledGeoIpDoesNotMakeTheServiceUnhealthy() {
        GeoIpProvider provider = mock(GeoIpProvider.class);

        assertThat(new GeoIpHealthIndicator(provider).health().getStatus())
                .isEqualTo(Status.UP);
    }

    @Test
    void enabledButUnavailableDatabaseMakesHealthFail() {
        GeoIpProvider provider = mock(GeoIpProvider.class);
        when(provider.isEnabled()).thenReturn(true);
        when(provider.isReady()).thenReturn(false);

        assertThat(new GeoIpHealthIndicator(provider).health().getStatus())
                .isEqualTo(Status.DOWN);
    }
}
