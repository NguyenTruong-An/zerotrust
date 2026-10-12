package com.zerotrust.risk.service;

import com.zerotrust.risk.validation.IpAddressNormalizer;

import java.util.Arrays;

final class IpCidr {

    private final byte[] networkAddress;
    private final int prefixLength;

    private IpCidr(byte[] networkAddress, int prefixLength) {
        this.networkAddress = mask(networkAddress, prefixLength);
        this.prefixLength = prefixLength;
    }

    static IpCidr parse(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("CIDR must not be blank");
        }

        String[] parts = value.trim().split("/", -1);
        if (parts.length != 2 || parts[1].isBlank()) {
            throw new IllegalArgumentException("CIDR must include a prefix length: " + value);
        }

        byte[] address = parseAddress(parts[0]);
        int addressBits = address.length * Byte.SIZE;
        int prefix;
        try {
            prefix = Integer.parseInt(parts[1]);
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("CIDR prefix is invalid: " + value, exception);
        }
        if (prefix < 0 || prefix > addressBits) {
            throw new IllegalArgumentException("CIDR prefix is out of range: " + value);
        }
        return new IpCidr(address, prefix);
    }

    boolean contains(String address) {
        byte[] candidate = parseAddress(address);
        return candidate.length == networkAddress.length
                && Arrays.equals(mask(candidate, prefixLength), networkAddress);
    }

    static void validateAddress(String value) {
        parseAddress(value);
    }

    private static byte[] parseAddress(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("IP address must not be blank");
        }
        return IpAddressNormalizer.parseLiteral(value.trim()).getAddress();
    }

    private static byte[] mask(byte[] address, int prefixLength) {
        byte[] result = address.clone();
        int fullBytes = prefixLength / Byte.SIZE;
        int remainingBits = prefixLength % Byte.SIZE;

        if (remainingBits > 0 && fullBytes < result.length) {
            int mask = 0xFF << (Byte.SIZE - remainingBits);
            result[fullBytes] = (byte) (result[fullBytes] & mask);
            fullBytes++;
        }
        Arrays.fill(result, fullBytes, result.length, (byte) 0);
        return result;
    }
}
