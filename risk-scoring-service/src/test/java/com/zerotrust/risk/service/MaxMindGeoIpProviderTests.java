package com.zerotrust.risk.service;

import com.zerotrust.risk.config.GeoIpProperties;
import com.zerotrust.risk.domain.GeoIpLookupStatus;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class MaxMindGeoIpProviderTests {

    @Test
    void disabledProviderDoesNotRequireOrOpenAnyDatabase() {
        MaxMindGeoIpProvider provider = new MaxMindGeoIpProvider(new GeoIpProperties());

        assertThat(provider.isEnabled()).isFalse();
        assertThat(provider.isReady()).isTrue();
        assertThat(provider.lookup("8.8.8.8").status()).isEqualTo(GeoIpLookupStatus.DISABLED);
    }

    @Test
    void configuredButMissingDatabaseFailsSafe() {
        GeoIpProperties properties = new GeoIpProperties();
        properties.setEnabled(true);
        properties.setCityDatabasePath("missing/GeoLite2-City.mmdb");
        MaxMindGeoIpProvider provider = new MaxMindGeoIpProvider(properties);

        assertThat(provider.isEnabled()).isTrue();
        assertThat(provider.isReady()).isFalse();
        assertThat(provider.lookup("8.8.8.8").status())
                .isEqualTo(GeoIpLookupStatus.UNAVAILABLE);
    }
}
