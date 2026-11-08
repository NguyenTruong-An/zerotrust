package com.zerotrust.zerotrust.config;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "app.public-demo")
public record PublicDemoProperties(
        @DefaultValue("LAB") @NotNull Mode mode,
        String academicReadOnly
) {
    public enum Mode { LAB, PUBLIC_DEMO }

    public boolean enabled() {
        return mode == Mode.PUBLIC_DEMO;
    }

    @AssertTrue(message = "PUBLIC_DEMO requires academic-read-only=true; LAB must not declare this flag")
    public boolean isReadOnlyContractValid() {
        return enabled() ? "true".equals(academicReadOnly)
                : academicReadOnly == null || academicReadOnly.isBlank();
    }
}
