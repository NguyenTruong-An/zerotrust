package com.zerotrust.risk.service;

import com.zerotrust.risk.config.DeviceFingerprintProperties;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;

@Service
public class DeviceFingerprintHasher {

    private static final String ALGORITHM = "HmacSHA256";

    private final SecretKeySpec key;

    public DeviceFingerprintHasher(DeviceFingerprintProperties properties) {
        this.key = new SecretKeySpec(
                properties.getPepper().getBytes(StandardCharsets.UTF_8),
                ALGORITHM
        );
    }

    public String hash(String subjectId, String deviceId) {
        String normalizedSubjectId = requireText(subjectId, "subjectId");
        String normalizedDeviceId = requireText(deviceId, "deviceId");
        String scopedFingerprint = normalizedSubjectId + '\0' + normalizedDeviceId;

        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(key);
            return HexFormat.of().formatHex(
                    mac.doFinal(scopedFingerprint.getBytes(StandardCharsets.UTF_8))
            );
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("HMAC-SHA-256 is not available", exception);
        }
    }

    private String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value.trim();
    }
}
