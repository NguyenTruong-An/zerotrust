package com.zerotrust.risk.service;

import com.zerotrust.risk.config.NetworkRiskProperties;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.GeoIpLocation;
import com.zerotrust.risk.domain.GeoIpLookupResult;
import com.zerotrust.risk.domain.GeoIpLookupStatus;
import com.zerotrust.risk.domain.NetworkRiskAssessment;
import com.zerotrust.risk.domain.NetworkRiskBand;
import com.zerotrust.risk.domain.NetworkRiskSource;
import com.zerotrust.risk.domain.NetworkRiskUnavailableReason;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Service
public class NetworkRiskCalculator {

    private final NetworkRiskProperties properties;
    private final List<IpCidr> trustedNetworks;
    private final List<IpCidr> elevatedRiskNetworks;
    private final List<IpCidr> highRiskNetworks;
    private final Set<String> trustedCountryCodes;
    private final Set<String> elevatedRiskCountryCodes;
    private final Set<String> highRiskCountryCodes;
    private final GeoIpProvider geoIpProvider;

    public NetworkRiskCalculator(NetworkRiskProperties properties, GeoIpProvider geoIpProvider) {
        this.properties = properties;
        this.geoIpProvider = geoIpProvider;
        this.trustedNetworks = parseCidrs(properties.getTrustedCidrs(), "trusted-cidrs");
        this.elevatedRiskNetworks = parseCidrs(
                properties.getElevatedRiskCidrs(),
                "elevated-risk-cidrs"
        );
        this.highRiskNetworks = parseCidrs(properties.getHighRiskCidrs(), "high-risk-cidrs");
        this.trustedCountryCodes = normalizeCountryCodes(
                properties.getTrustedCountryCodes(),
                "trusted-country-codes"
        );
        this.elevatedRiskCountryCodes = normalizeCountryCodes(
                properties.getElevatedRiskCountryCodes(),
                "elevated-risk-country-codes"
        );
        this.highRiskCountryCodes = normalizeCountryCodes(
                properties.getHighRiskCountryCodes(),
                "high-risk-country-codes"
        );
    }

    public NetworkRiskAssessment calculate(LoginContext context) {
        if (!properties.isEnabled()) {
            return NetworkRiskAssessment.unavailable(
                    NetworkRiskUnavailableReason.PROVIDER_DISABLED
            );
        }

        String ipAddress = context.ipAddress();
        try {
            IpCidr.validateAddress(ipAddress);
            if (matches(highRiskNetworks, ipAddress)) {
                return assessment(
                        properties.getHighScore(),
                        NetworkRiskBand.HIGH,
                        NetworkRiskSource.CIDR,
                        null
                );
            }
            if (matches(elevatedRiskNetworks, ipAddress)) {
                return assessment(
                        properties.getElevatedScore(),
                        NetworkRiskBand.ELEVATED,
                        NetworkRiskSource.CIDR,
                        null
                );
            }
            if (matches(trustedNetworks, ipAddress)) {
                return assessment(
                        BigDecimal.ZERO,
                        NetworkRiskBand.TRUSTED,
                        NetworkRiskSource.CIDR,
                        null
                );
            }
            if (!geoIpProvider.isEnabled() || !isPublicAddress(ipAddress)) {
                return defaultAssessment();
            }
            return assessmentFromGeoIp(geoIpProvider.lookup(ipAddress));
        } catch (IllegalArgumentException exception) {
            return NetworkRiskAssessment.unavailable(
                    NetworkRiskUnavailableReason.INVALID_IP_ADDRESS
            );
        }
    }

    private NetworkRiskAssessment assessmentFromGeoIp(GeoIpLookupResult lookup) {
        if (lookup.status() != GeoIpLookupStatus.AVAILABLE) {
            return NetworkRiskAssessment.unavailable(
                    NetworkRiskUnavailableReason.GEOIP_UNAVAILABLE
            );
        }

        GeoIpLocation location = lookup.location();
        String countryCode = location.countryCode();
        if (countryCode == null) {
            return NetworkRiskAssessment.unavailable(
                    NetworkRiskUnavailableReason.GEOIP_UNAVAILABLE
            );
        }
        if (highRiskCountryCodes.contains(countryCode)) {
            return assessment(
                    properties.getHighScore(),
                    NetworkRiskBand.HIGH,
                    NetworkRiskSource.GEOIP,
                    location
            );
        }
        if (elevatedRiskCountryCodes.contains(countryCode)) {
            return assessment(
                    properties.getElevatedScore(),
                    NetworkRiskBand.ELEVATED,
                    NetworkRiskSource.GEOIP,
                    location
            );
        }
        if (trustedCountryCodes.contains(countryCode)) {
            return assessment(
                    BigDecimal.ZERO,
                    NetworkRiskBand.TRUSTED,
                    NetworkRiskSource.GEOIP,
                    location
            );
        }
        return assessment(
                properties.getDefaultScore(),
                NetworkRiskBand.DEFAULT,
                NetworkRiskSource.GEOIP,
                location
        );
    }

    private NetworkRiskAssessment defaultAssessment() {
        return assessment(
                properties.getDefaultScore(),
                NetworkRiskBand.DEFAULT,
                NetworkRiskSource.DEFAULT_POLICY,
                null
        );
    }

    private static NetworkRiskAssessment assessment(
            BigDecimal score,
            NetworkRiskBand band,
            NetworkRiskSource source,
            GeoIpLocation location
    ) {
        return NetworkRiskAssessment.available(score, band, source, location);
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

    private static Set<String> normalizeCountryCodes(List<String> values, String propertyName) {
        Set<String> result = new HashSet<>();
        for (String value : values) {
            if (value == null || !value.trim().toUpperCase(Locale.ROOT).matches("[A-Z]{2}")) {
                throw new IllegalArgumentException(
                        "Invalid risk.policy.network-risk." + propertyName + ": " + value
                );
            }
            result.add(value.trim().toUpperCase(Locale.ROOT));
        }
        return Set.copyOf(result);
    }

    private static boolean isPublicAddress(String ipAddress) {
        try {
            InetAddress address = InetAddress.getByName(ipAddress);
            return !address.isAnyLocalAddress()
                    && !address.isLoopbackAddress()
                    && !address.isLinkLocalAddress()
                    && !address.isSiteLocalAddress()
                    && !address.isMulticastAddress();
        } catch (UnknownHostException exception) {
            return false;
        }
    }
}
