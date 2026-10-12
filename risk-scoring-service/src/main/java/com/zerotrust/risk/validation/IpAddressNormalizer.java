package com.zerotrust.risk.validation;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

/** Canonicalizes IP literals without hostname resolution or accepting scope IDs. */
public final class IpAddressNormalizer {

    private static final Pattern IPV4_CHARACTERS = Pattern.compile("[0-9.]+");
    private static final Pattern IPV6_CHARACTERS = Pattern.compile("[0-9a-fA-F:.]+");

    private IpAddressNormalizer() {
    }

    public static String normalize(String value) {
        return parseLiteral(value).getHostAddress();
    }

    /** Parses only literals accepted by the API; hostnames, scope IDs and mapped IPv6 stay rejected. */
    public static InetAddress parseLiteral(String value) {
        if (value == null || value.isEmpty() || value.length() > 45) {
            throw invalidAddress();
        }

        try {
            if (value.indexOf(':') < 0) {
                return InetAddress.getByAddress(parseIpv4(value));
            }
            if (!IPV6_CHARACTERS.matcher(value).matches()) {
                throw invalidAddress();
            }
            if (value.indexOf('.') >= 0) {
                // Validate the dotted tail as four decimal octets, never Java's abbreviated forms.
                parseIpv4(value.substring(value.lastIndexOf(':') + 1));
            }
            // A colon-containing literal with this whitelist cannot trigger a DNS lookup.
            InetAddress address = InetAddress.getByName(value);
            if (!(address instanceof Inet6Address)) {
                // Preserve the API's rejection of IPv4-mapped IPv6 addresses.
                throw invalidAddress();
            }
            return address;
        } catch (UnknownHostException exception) {
            throw invalidAddress();
        }
    }

    private static byte[] parseIpv4(String value) {
        if (!IPV4_CHARACTERS.matcher(value).matches()) {
            throw invalidAddress();
        }
        String[] octets = value.split("\\.", -1);
        if (octets.length != 4) {
            throw invalidAddress();
        }
        byte[] address = new byte[4];
        for (int index = 0; index < octets.length; index++) {
            String octet = octets[index];
            if (octet.isEmpty() || octet.length() > 3) {
                throw invalidAddress();
            }
            int parsed = Integer.parseInt(octet);
            if (parsed > 255) {
                throw invalidAddress();
            }
            address[index] = (byte) parsed;
        }
        return address;
    }

    private static IllegalArgumentException invalidAddress() {
        return new IllegalArgumentException("Invalid IP address literal");
    }
}
