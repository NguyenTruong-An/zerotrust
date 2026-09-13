package com.zerotrust.risk.config;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.net.URI;

@Validated
@ConfigurationProperties("risk.security")
public record RiskApiSecurityProperties(
        @NotNull URI issuerUri,
        @NotNull URI jwkSetUri,
        @NotBlank String audience,
        @NotBlank String allowedClientId,
        boolean requireHttps
) {
    @AssertTrue(message = "JWT endpoints must be absolute HTTPS URLs; HTTP is only allowed with require-https=false")
    public boolean isEndpointConfigurationValid() {
        return validEndpoint(issuerUri) && validEndpoint(jwkSetUri);
    }

    private boolean validEndpoint(URI uri) {
        if (uri == null) return true; // @NotNull owns this validation.
        return uri.getHost() != null && uri.getRawUserInfo() == null
                && uri.getRawQuery() == null && uri.getRawFragment() == null
                && ("https".equalsIgnoreCase(uri.getScheme())
                || (!requireHttps && "http".equalsIgnoreCase(uri.getScheme())));
    }
}
