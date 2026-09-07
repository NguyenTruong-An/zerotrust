package com.zerotrust.risk.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "risk.device-fingerprint")
@Getter
@Setter
public class DeviceFingerprintProperties {

    @NotBlank
    @Size(min = 32)
    private String pepper;

}
