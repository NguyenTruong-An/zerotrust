package com.zerotrust.risk.validation;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IpAddressNormalizerTests {

    private final IpAddressValidator validator = new IpAddressValidator();

    @ParameterizedTest
    @CsvSource({
            "203.000.113.010, 203.0.113.10",
            "000.000.000.000, 0.0.0.0",
            "255.255.255.255, 255.255.255.255",
            "2001:0DB8::ABCD, 2001:db8:0:0:0:0:0:abcd",
            "::1, 0:0:0:0:0:0:0:1",
            "::, 0:0:0:0:0:0:0:0",
            "2001:db8::192.0.2.1, 2001:db8:0:0:0:0:c000:201"
    })
    void canonicalizesValidLiteralsAcceptedByTheApi(String input, String expected) {
        assertThat(validator.isValid(input, null)).isTrue();
        assertThat(IpAddressNormalizer.normalize(input)).isEqualTo(expected);
        assertThat(IpAddressNormalizer.normalize(expected)).isEqualTo(expected);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "localhost", "example.invalid", "deadbeef", "2130706433", "127.1",
            "1.2.3", "1.2.3.4.5", "256.0.0.1", "1..2.3", "1.2.3.", "0001.2.3.4",
            "-1.2.3.4", "0x7f.0.0.1", " 203.0.113.10", "203.0.113.10 ",
            "[2001:db8::1]", "fe80::1%eth0", "fe80::1%1", "2001:::1",
            "2001:db8::g", "2001:db8:0:0:0:0:0:0:1", "2001:db8::192.0.2",
            "::ffff:192.0.2.1", "::ffff:c000:201"
    })
    void rejectsNonLiteralsAndMalformedAddresses(String input) {
        assertThat(validator.isValid(input, null)).isFalse();
        assertThatThrownBy(() -> IpAddressNormalizer.normalize(input))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid IP address literal");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = " ")
    void normalizerRejectsMissingAddresses(String input) {
        assertThatThrownBy(() -> IpAddressNormalizer.normalize(input))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void leavesRequiredFieldValidationToNotBlank() {
        assertThat(validator.isValid(null, null)).isTrue();
        assertThat(validator.isValid("", null)).isTrue();
        assertThat(validator.isValid(" ", null)).isTrue();
    }
}
