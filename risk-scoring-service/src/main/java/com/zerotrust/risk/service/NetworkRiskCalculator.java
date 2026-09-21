package com.zerotrust.risk.service;

import com.zerotrust.risk.config.NetworkRiskProperties;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.NetworkRiskAssessment;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.List;

@Service
public class NetworkRiskCalculator {

    private final NetworkRiskProperties properties;
    private final List<IpCidr> trustedNetworks;
    private final List<IpCidr> elevatedRiskNetworks;
    private final List<IpCidr> highRiskNetworks;

    public NetworkRiskCalculator(NetworkRiskProperties properties) {
        this.properties = properties;
        this.trustedNetworks = parseCidrs(properties.getTrustedCidrs(), "trusted-cidrs");
        this.elevatedRiskNetworks = parseCidrs(
                properties.getElevatedRiskCidrs(),
                "elevated-risk-cidrs"
        );
        this.highRiskNetworks = parseCidrs(properties.getHighRiskCidrs(), "high-risk-cidrs");
    }

    public NetworkRiskAssessment calculate(LoginContext context) {
        if (!properties.isEnabled()) {
            return NetworkRiskAssessment.unavailable();
        }

        String ipAddress = context.ipAddress();
        try {
            IpCidr.validateAddress(ipAddress);
            if (matches(highRiskNetworks, ipAddress)) {
                return NetworkRiskAssessment.available(properties.getHighScore());
            }
            if (matches(elevatedRiskNetworks, ipAddress)) {
                return NetworkRiskAssessment.available(properties.getElevatedScore());
            }
            if (matches(trustedNetworks, ipAddress)) {
                return NetworkRiskAssessment.available(BigDecimal.ZERO);
            }
            return NetworkRiskAssessment.available(properties.getDefaultScore());
        } catch (IllegalArgumentException exception) {
            return NetworkRiskAssessment.unavailable();
        }
    }

    private static List<IpCidr> parseCidrs(List<String> values, String propertyName) {
        try {
            return values.stream()
                    .filter(value -> value != null && !value.isBlank())
                    .map(IpCidr::parse)
                    .toList();
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException(
                    "Invalid risk.policy.network-risk." + propertyName + ": "
                            + exception.getMessage(),
                    exception
            );
        }
    }

    private static boolean matches(List<IpCidr> networks, String ipAddress) {
        return networks.stream().anyMatch(network -> network.contains(ipAddress));
    }
}
