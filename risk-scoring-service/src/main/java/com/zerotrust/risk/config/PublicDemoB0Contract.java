package com.zerotrust.risk.config;

import org.springframework.core.env.Environment;
import java.math.BigDecimal;

/** Owner-approved Public Demo policy; the research/Lab scoring configuration stays configurable. */
final class PublicDemoB0Contract {
    private PublicDemoB0Contract() { }

    static void validate(Environment environment) {
        try {
            if (!"BASELINE_B0".equals(environment.getProperty("risk.policy.model"))) throw new IllegalStateException();
            for (String factor : new String[]{"device", "network", "temporal", "authentication-history"}) {
                equal(environment, "risk.policy.weights." + factor, "0.25");
            }
            equal(environment, "risk.policy.thresholds.medium-minimum", "40");
            equal(environment, "risk.policy.thresholds.high-minimum", "75");
        } catch (RuntimeException ignored) {
            throw new IllegalStateException("Public Demo requires approved BASELINE_B0 weights/thresholds (values redacted)");
        }
    }

    private static void equal(Environment environment, String key, String expected) {
        String value = environment.getProperty(key);
        if (value == null || new BigDecimal(value).compareTo(new BigDecimal(expected)) != 0) throw new IllegalStateException();
    }
}
