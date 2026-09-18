package com.zerotrust.keycloak.risk.context;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

public final class SecureRandomDeviceIdGenerator implements DeviceIdGenerator {

    private static final int RANDOM_BYTES = 32;

    private final SecureRandom secureRandom;

    public SecureRandomDeviceIdGenerator() {
        this(new SecureRandom());
    }

    SecureRandomDeviceIdGenerator(SecureRandom secureRandom) {
        this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom must not be null");
    }

    @Override
    public String generate() {
        byte[] randomBytes = new byte[RANDOM_BYTES];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
}
