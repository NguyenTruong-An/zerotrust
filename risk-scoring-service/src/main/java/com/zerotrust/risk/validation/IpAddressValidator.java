package com.zerotrust.risk.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class IpAddressValidator implements ConstraintValidator<ValidIpAddress, String> {

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.isBlank()) {
            return true;
        }

        try {
            IpAddressNormalizer.normalize(value);
            return true;
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }
}
