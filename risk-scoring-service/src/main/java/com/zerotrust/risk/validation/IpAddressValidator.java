package com.zerotrust.risk.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class IpAddressValidator implements ConstraintValidator<ValidIpAddress, String> {

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.isBlank()) {
            return true;
        }

        return value.indexOf(':') >= 0 ? isIpv6(value) : isIpv4(value);
    }

    private boolean isIpv4(String value) {
        if (!value.matches("[0-9.]+")) {
            return false;
        }

        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }

        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) {
                return false;
            }
            int octet = Integer.parseInt(part);
            if (octet > 255) {
                return false;
            }
        }
        return true;
    }

    private boolean isIpv6(String value) {
        if (!value.matches("[0-9a-fA-F:.]+")) {
            return false;
        }

        try {
            InetAddress address = InetAddress.getByName(value);
            return address instanceof Inet6Address;
        } catch (UnknownHostException exception) {
            return false;
        }
    }
}
