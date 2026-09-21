package com.zerotrust.risk.service;

import com.zerotrust.risk.config.NetworkRiskProperties;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.NetworkRiskAssessment;
import com.zerotrust.risk.domain.NetworkRiskStatus;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class NetworkRiskCalculatorTests {

    @Test
    void returnsUnavailableWhenTheProviderIsDisabled() {
        NetworkRiskProperties properties = properties(false);

        NetworkRiskAssessment result = new NetworkRiskCalculator(properties)
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

        NetworkRiskAssessment result = new NetworkRiskCalculator(properties)
                .calculate(context("10.20.14.9"));

        assertThat(result.riskScore()).isEqualByComparingTo(BigDecimal.ZERO);
    }

    @Test
    void supportsIpv6Networks() {
        NetworkRiskProperties properties = properties(true);
        properties.setElevatedRiskCidrs(List.of("2001:db8:1234::/48"));

        NetworkRiskAssessment result = new NetworkRiskCalculator(properties)
                .calculate(context("2001:db8:1234:abcd::9"));

        assertThat(result.riskScore()).isEqualByComparingTo("50");
    }

    @Test
    void highRiskWinsWhenConfiguredNetworksOverlap() {
        NetworkRiskProperties properties = properties(true);
        properties.setTrustedCidrs(List.of("198.51.100.0/24"));
        properties.setElevatedRiskCidrs(List.of("198.51.100.0/25"));
        properties.setHighRiskCidrs(List.of("198.51.100.64/26"));

        NetworkRiskAssessment result = new NetworkRiskCalculator(properties)
                .calculate(context("198.51.100.70"));

        assertThat(result.riskScore()).isEqualByComparingTo("100");
    }

    @Test
    void differentAddressFamiliesDoNotMatch() {
        NetworkRiskProperties properties = properties(true);
        properties.setHighRiskCidrs(List.of("2001:db8::/32"));

        NetworkRiskAssessment result = new NetworkRiskCalculator(properties)
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

        assertThatThrownBy(() -> new NetworkRiskCalculator(properties))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("risk.policy.network-risk.high-risk-cidrs");
    }

    private NetworkRiskCalculator calculator() {
        return new NetworkRiskCalculator(properties(true));
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
