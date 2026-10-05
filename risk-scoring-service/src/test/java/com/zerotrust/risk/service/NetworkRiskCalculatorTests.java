package com.zerotrust.risk.service;

import com.zerotrust.risk.config.NetworkRiskProperties;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.GeoIpLocation;
import com.zerotrust.risk.domain.GeoIpLookupResult;
import com.zerotrust.risk.domain.NetworkRiskAssessment;
import com.zerotrust.risk.domain.NetworkRiskBand;
import com.zerotrust.risk.domain.NetworkRiskSource;
import com.zerotrust.risk.domain.NetworkRiskStatus;
import com.zerotrust.risk.domain.NetworkRiskUnavailableReason;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class NetworkRiskCalculatorTests {

    @Test
    void returnsUnavailableWhenTheProviderIsDisabled() {
        NetworkRiskProperties properties = properties(false);

        NetworkRiskAssessment result = new NetworkRiskCalculator(properties, disabledGeoIp())
                .calculate(context("203.0.113.10"));

        assertThat(result.status()).isEqualTo(NetworkRiskStatus.UNAVAILABLE);
        assertThat(result.riskScore()).isNull();
    }

    @Test
    void returnsTheDefaultScoreForAnUnclassifiedAddress() {
        NetworkRiskAssessment result = calculator().calculate(context("203.0.113.10"));

        assertThat(result.status()).isEqualTo(NetworkRiskStatus.AVAILABLE);
        assertThat(result.riskScore()).isEqualByComparingTo("25");
    }

    @Test
    void returnsZeroForAnExplicitlyTrustedIpv4Network() {
        NetworkRiskProperties properties = properties(true);
        properties.setTrustedCidrs(List.of("10.20.0.0/16"));

        NetworkRiskAssessment result = new NetworkRiskCalculator(properties, disabledGeoIp())
                .calculate(context("10.20.14.9"));

        assertThat(result.riskScore()).isEqualByComparingTo(BigDecimal.ZERO);
    }

    @Test
    void supportsIpv6Networks() {
        NetworkRiskProperties properties = properties(true);
        properties.setElevatedRiskCidrs(List.of("2001:db8:1234::/48"));

        NetworkRiskAssessment result = new NetworkRiskCalculator(properties, disabledGeoIp())
                .calculate(context("2001:db8:1234:abcd::9"));

        assertThat(result.riskScore()).isEqualByComparingTo("50");
    }

    @Test
    void highRiskWinsWhenConfiguredNetworksOverlap() {
        NetworkRiskProperties properties = properties(true);
        properties.setTrustedCidrs(List.of("198.51.100.0/24"));
        properties.setElevatedRiskCidrs(List.of("198.51.100.0/25"));
        properties.setHighRiskCidrs(List.of("198.51.100.64/26"));

        NetworkRiskAssessment result = new NetworkRiskCalculator(properties, disabledGeoIp())
                .calculate(context("198.51.100.70"));

        assertThat(result.riskScore()).isEqualByComparingTo("100");
        assertThat(result.band()).isEqualTo(NetworkRiskBand.HIGH);
        assertThat(result.requiresStepUp()).isTrue();
    }

    @Test
    void differentAddressFamiliesDoNotMatch() {
        NetworkRiskProperties properties = properties(true);
        properties.setHighRiskCidrs(List.of("2001:db8::/32"));

        NetworkRiskAssessment result = new NetworkRiskCalculator(properties, disabledGeoIp())
                .calculate(context("203.0.113.10"));

        assertThat(result.riskScore()).isEqualByComparingTo("25");
    }

    @Test
    void invalidRuntimeAddressFailsSafe() {
        NetworkRiskAssessment result = calculator().calculate(context("not-an-ip"));

        assertThat(result.status()).isEqualTo(NetworkRiskStatus.UNAVAILABLE);
        assertThat(result.riskScore()).isNull();
    }

    @Test
    void invalidConfiguredCidrFailsStartup() {
        NetworkRiskProperties properties = properties(true);
        properties.setHighRiskCidrs(List.of("203.0.113.0/99"));

        assertThatThrownBy(() -> new NetworkRiskCalculator(properties, disabledGeoIp()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("risk.policy.network-risk.high-risk-cidrs");
    }

    @Test
    void trustedCountryUsesGeoIpWithoutPersistingTheRawAddress() {
        NetworkRiskProperties properties = properties(true);
        properties.setTrustedCountryCodes(List.of("vn"));
        GeoIpProvider geoIpProvider = enabledGeoIp(new GeoIpLocation(
                "VN", "Ho Chi Minh City", "Asia/Ho_Chi_Minh", 50, 7552L, "Viettel"
        ));

        NetworkRiskAssessment result = new NetworkRiskCalculator(properties, geoIpProvider)
                .calculate(context("8.8.8.8"));

        assertThat(result.riskScore()).isEqualByComparingTo(BigDecimal.ZERO);
        assertThat(result.band()).isEqualTo(NetworkRiskBand.TRUSTED);
        assertThat(result.source()).isEqualTo(NetworkRiskSource.GEOIP);
        assertThat(result.geoIpLocation().countryCode()).isEqualTo("VN");
    }

    @Test
    void highRiskCountryRequiresStepUpEvenWhenItsWeightedContributionWouldBeLow() {
        NetworkRiskProperties properties = properties(true);
        properties.setHighRiskCountryCodes(List.of("US"));
        GeoIpProvider geoIpProvider = enabledGeoIp(new GeoIpLocation(
                "US", null, "America/Chicago", 1000, null, null
        ));

        NetworkRiskAssessment result = new NetworkRiskCalculator(properties, geoIpProvider)
                .calculate(context("8.8.8.8"));

        assertThat(result.riskScore()).isEqualByComparingTo("100");
        assertThat(result.band()).isEqualTo(NetworkRiskBand.HIGH);
        assertThat(result.requiresStepUp()).isTrue();
    }

    @Test
    void missingGeoIpRecordFailsSafeInsteadOfReturningTheDefaultScore() {
        NetworkRiskProperties properties = properties(true);
        GeoIpProvider geoIpProvider = mock(GeoIpProvider.class);
        when(geoIpProvider.isEnabled()).thenReturn(true);
        when(geoIpProvider.lookup("8.8.8.8")).thenReturn(GeoIpLookupResult.notFound());

        NetworkRiskAssessment result = new NetworkRiskCalculator(properties, geoIpProvider)
                .calculate(context("8.8.8.8"));

        assertThat(result.status()).isEqualTo(NetworkRiskStatus.UNAVAILABLE);
        assertThat(result.unavailableReason())
                .isEqualTo(NetworkRiskUnavailableReason.GEOIP_UNAVAILABLE);
    }

    @Test
    void privateAddressUsesCidrDefaultWithoutCallingGeoIp() {
        NetworkRiskProperties properties = properties(true);
        GeoIpProvider geoIpProvider = mock(GeoIpProvider.class);
        when(geoIpProvider.isEnabled()).thenReturn(true);

        NetworkRiskAssessment result = new NetworkRiskCalculator(properties, geoIpProvider)
                .calculate(context("10.10.10.10"));

        assertThat(result.riskScore()).isEqualByComparingTo("25");
        assertThat(result.source()).isEqualTo(NetworkRiskSource.DEFAULT_POLICY);
        verify(geoIpProvider, never()).lookup("10.10.10.10");
    }

    private NetworkRiskCalculator calculator() {
        return new NetworkRiskCalculator(properties(true), disabledGeoIp());
    }

    private GeoIpProvider disabledGeoIp() {
        GeoIpProvider provider = mock(GeoIpProvider.class);
        when(provider.isEnabled()).thenReturn(false);
        return provider;
    }

    private GeoIpProvider enabledGeoIp(GeoIpLocation location) {
        GeoIpProvider provider = mock(GeoIpProvider.class);
        when(provider.isEnabled()).thenReturn(true);
        when(provider.lookup("8.8.8.8")).thenReturn(GeoIpLookupResult.available(location));
        return provider;
    }

    private NetworkRiskProperties properties(boolean enabled) {
        NetworkRiskProperties properties = new NetworkRiskProperties();
        properties.setEnabled(enabled);
        properties.setDefaultScore(new BigDecimal("25"));
        properties.setElevatedScore(new BigDecimal("50"));
        properties.setHighScore(new BigDecimal("100"));
        return properties;
    }

    private LoginContext context(String ipAddress) {
        return new LoginContext(
                "subject-1",
                "authentication-session-id",
                "zerotrust-spa",
                ipAddress,
                "Mozilla/5.0",
                "device-1",
                Instant.parse("2026-09-18T08:00:00Z")
        );
    }
}
