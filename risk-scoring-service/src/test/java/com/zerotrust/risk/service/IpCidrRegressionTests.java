package com.zerotrust.risk.service;

import com.zerotrust.risk.config.NetworkRiskProperties;
import com.zerotrust.risk.domain.NetworkRiskBand;
import com.zerotrust.risk.domain.NetworkRiskStatus;
import com.zerotrust.risk.dto.request.RiskEvaluationRequest;
import com.zerotrust.risk.validation.IpAddressNormalizer;
import jakarta.validation.Validation;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.InetAddress;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

class IpCidrRegressionTests {

    // RFC 4291's dotted tail occupies the last 32 bits: c0 00 02 01.
    // Expected bits and the BigInteger prefix oracle never call a production parser.
    private static final byte[] IPV6_BYTES = HexFormat.of().parseHex("20010db80000000000000000c0000201");
    private static final List<String> EQUIVALENT_IPV6 = List.of(
            "2001:db8::c000:201", "2001:db8::192.0.2.1",
            "2001:0db8:0000:0000:0000:0000:c000:0201",
            "2001:db8:0:0:0:0:192.0.2.1", "2001:DB8::C000:0201",
            "2001:db8::192.000.002.001");
    private static ValidatorFactory validatorFactory;

    @BeforeAll
    static void validation() {
        validatorFactory = Validation.buildDefaultValidatorFactory();
    }

    @AfterAll
    static void closeValidation() {
        validatorFactory.close();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "2001:db8::c000:201", "2001:db8::192.0.2.1",
            "2001:0db8:0000:0000:0000:0000:c000:0201",
            "2001:db8:0:0:0:0:192.0.2.1", "2001:DB8::C000:0201",
            "2001:db8::192.000.002.001"
    })
    void equivalentLiteralsMatchAnIndependentlyEncodedHostNetwork(String input) {
        assertThat(validatorFactory.getValidator().validate(request(input))).isEmpty();
        assertThat(IpAddressNormalizer.normalize(input)).isEqualTo("2001:db8:0:0:0:0:c000:201");
        IpCidr host = IpCidr.parse(expanded(IPV6_BYTES) + "/128");
        assertThat(host.contains(input)).isTrue();
        assertThat(host.contains("2001:db8::192.0.2.0")).isFalse();
        IpCidr spelledHost = IpCidr.parse(input + "/128");
        for (String equivalent : EQUIVALENT_IPV6) {
            assertThat(spelledHost.contains(equivalent)).as("CIDR=%s candidate=%s", input, equivalent).isTrue();
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 7, 8, 9, 31, 32, 63, 64, 65, 95, 96, 97, 119, 120, 121, 127, 128})
    void ipv6PrefixesAndBothSpellingsMatchTheUnsignedBinaryOracle(int prefix) {
        byte[] network = HexFormat.of().parseHex("20010db8abcd123456789abcdef01234");
        IpCidr hexadecimal = IpCidr.parse(expanded(network) + "/" + prefix);
        IpCidr dotted = IpCidr.parse(mixed(network) + "/" + prefix);
        for (int bit = -1; bit < 128; bit++) {
            byte[] candidate = network.clone();
            if (bit >= 0) { candidate[bit / 8] ^= (byte) (1 << (7 - bit % 8)); }
            boolean expected = member(network, candidate, prefix);
            for (String address : List.of(expanded(candidate), mixed(candidate))) {
                assertThat(hexadecimal.contains(address)).as("hex /%s bit=%s candidate=%s", prefix, bit, address)
                        .isEqualTo(expected);
                assertThat(dotted.contains(address)).as("mixed /%s bit=%s candidate=%s", prefix, bit, address)
                        .isEqualTo(expected);
            }
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 7, 8, 9, 15, 16, 17, 24, 25, 31, 32})
    void ipv4PrefixesKeepDecimalAndLeadingZeroSemantics(int prefix) {
        byte[] network = {(byte) 198, 51, 100, 70};
        IpCidr cidr = IpCidr.parse("198.051.100.070/" + prefix);
        for (int bit = -1; bit < 32; bit++) {
            byte[] candidate = network.clone();
            if (bit >= 0) { candidate[bit / 8] ^= (byte) (1 << (7 - bit % 8)); }
            assertThat(cidr.contains(ipv4(candidate, 0))).isEqualTo(member(network, candidate, prefix));
        }
        assertThat(cidr.contains("198.051.100.070")).isTrue();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {
            " ", "\t", "\n", "localhost", "example.invalid", "deadbeef", "127.1", "256.1.2.3",
            "2001:::1", "2001:db8::g", "2001:db8:0:0:0:0:0:0:1", "2001:db8::1::2",
            "2001:db8::192.0.2", "2001:db8::192.0.2.256", "2001:db8::0000.0.2.1",
            "fe80::1%eth0", "fe80::1%1", "[2001:db8::1]", "::ffff:192.0.2.1", "::ffff:c000:201"
    })
    void invalidOrContractExcludedLiteralsRemainRejected(String input) {
        assertThat(validatorFactory.getValidator().validate(request(input))).isNotEmpty();
        assertThatThrownBy(() -> IpAddressNormalizer.normalize(input)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> IpCidr.validateAddress(input)).isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {
            " ", "2001:db8::", "2001:db8::/-1", "2001:db8::/129", "2001:db8::/64/1",
            "2001:db8::/1.0", "2001:db8::/ 64", "2001:db8::/", "192.0.2.1/33",
            "localhost/32", "fe80::1%eth0/64", "::ffff:c000:201/128", "::ffff:192.0.2.1/128"
    })
    void malformedCidrsStillFailConfiguration(String input) {
        assertThatThrownBy(() -> IpCidr.parse(input)).isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"2001:db8::c000:201", "2001:db8::192.0.2.1"})
    void highNetworkKeepsPrecedenceOverMixedTrustedAndElevatedCidrs(String input) {
        NetworkRiskProperties properties = properties();
        properties.setTrustedCidrs(List.of("2001:db8::192.0.2.1/128"));
        properties.setElevatedRiskCidrs(List.of("2001:db8::c000:201/128"));
        properties.setHighRiskCidrs(List.of("2001:db8::/32"));
        var actual = new NetworkRiskCalculator(properties, mock(GeoIpProvider.class))
                .calculate(request(input).toDomain(Instant.EPOCH));
        assertThat(actual.status()).isEqualTo(NetworkRiskStatus.AVAILABLE);
        assertThat(actual.band()).isEqualTo(NetworkRiskBand.HIGH);
        assertThat(actual.riskScore()).isEqualByComparingTo("100");
        assertThat(actual.requiresStepUp()).isTrue();
    }

    @ParameterizedTest
    @CsvSource({"::/0, 192.0.2.1", "0.0.0.0/0, ::192.0.2.1"})
    void zeroPrefixesNeverMatchADifferentAddressFamily(String cidr, String candidate) {
        assertThat(IpCidr.parse(cidr).contains(candidate)).isFalse();
    }

    @Test
    void cidrWhitespaceRemainsSeparateFromStrictRequestValidation() {
        String input = " 2001:db8::192.0.2.1 ";
        assertThat(validatorFactory.getValidator().validate(request(input))).isNotEmpty();
        assertThatThrownBy(() -> IpAddressNormalizer.normalize(input)).isInstanceOf(IllegalArgumentException.class);
        assertThat(IpCidr.parse(" 2001:db8:: /32 ").contains(input)).isTrue();
    }

    @Test
    void sharedLiteralParserReturnsTheIndependent128BitValueAndKeepsIpv4As32Bits() {
        for (String input : EQUIVALENT_IPV6) {
            assertThat(IpAddressNormalizer.parseLiteral(input).getAddress()).containsExactly(IPV6_BYTES);
        }
        assertThat(IpAddressNormalizer.parseLiteral("192.000.002.001").getAddress())
                .containsExactly((byte) 192, (byte) 0, (byte) 2, (byte) 1);
    }

    @Test
    void hostnamesAndScopeSyntaxAreRejectedBeforeAnyInetAddressResolutionCall() {
        try (var resolution = mockStatic(InetAddress.class)) {
            for (String input : List.of("localhost", "example.invalid", "deadbeef", "[2001:db8::1]", "fe80::1%eth0")) {
                assertThatThrownBy(() -> IpAddressNormalizer.parseLiteral(input))
                        .isInstanceOf(IllegalArgumentException.class);
            }
            resolution.verifyNoInteractions();
        }
    }

    private static RiskEvaluationRequest request(String ip) {
        return new RiskEvaluationRequest("qa-subject", "qa-session", "qa-client", ip, null, "qa-device");
    }

    private static NetworkRiskProperties properties() {
        NetworkRiskProperties properties = new NetworkRiskProperties();
        properties.setEnabled(true);
        properties.setDefaultScore(new BigDecimal("25"));
        properties.setElevatedScore(new BigDecimal("50"));
        properties.setHighScore(new BigDecimal("100"));
        return properties;
    }

    private static boolean member(byte[] network, byte[] candidate, int prefix) {
        int bits = network.length * Byte.SIZE;
        return new BigInteger(1, network).shiftRight(bits - prefix)
                .equals(new BigInteger(1, candidate).shiftRight(bits - prefix));
    }

    private static String expanded(byte[] bytes) {
        return IntStream.range(0, 8).mapToObj(i -> Integer.toHexString(
                ((bytes[2 * i] & 255) << 8) | (bytes[2 * i + 1] & 255))).collect(Collectors.joining(":"));
    }

    private static String mixed(byte[] bytes) {
        return IntStream.range(0, 6).mapToObj(i -> Integer.toHexString(
                ((bytes[2 * i] & 255) << 8) | (bytes[2 * i + 1] & 255)))
                .collect(Collectors.joining(":")) + ":" + ipv4(bytes, 12);
    }

    private static String ipv4(byte[] bytes, int offset) {
        return IntStream.range(offset, offset + 4).mapToObj(i -> Integer.toString(bytes[i] & 255))
                .collect(Collectors.joining("."));
    }
}
