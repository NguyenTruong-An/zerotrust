package com.zerotrust.keycloak.risk.context;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecureRandomDeviceIdGeneratorTest {

    @Test
    void generatesIndependentBase64UrlIdentifiersWith256BitsOfEntropy() {
        SecureRandomDeviceIdGenerator generator = new SecureRandomDeviceIdGenerator();

        String first = generator.generate();
        String second = generator.generate();

        assertEquals(43, first.length());
        assertTrue(first.matches("[A-Za-z0-9_-]+"));
        assertNotEquals(first, second);
    }
}
