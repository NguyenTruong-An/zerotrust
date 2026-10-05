package com.zerotrust.zerotrust.risk;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.time.Duration;
import java.util.Set;

@Component
@ConfigurationProperties("app.risk-admin")
@Getter
@Setter
public class RiskAdminProperties {
    private URI baseUrl;
    private URI tokenUri;
    private String clientId = "zerotrust-portal-risk-admin";
    private String clientSecret;
    private boolean allowHttp;
    private Duration connectTimeout = Duration.ofSeconds(3);
    private Duration readTimeout = Duration.ofSeconds(5);

    public boolean configured() {
        return validUri(baseUrl) && validUri(tokenUri)
                && clientId != null && !clientId.isBlank()
                && !Set.of("zerotrust-spa", "zerotrust-provisioner", "zerotrust-risk-caller").contains(clientId)
                && clientSecret != null && !clientSecret.isBlank();
    }

    private boolean validUri(URI uri) {
        return uri != null && uri.getHost() != null && uri.getRawUserInfo() == null
                && uri.getRawQuery() == null && uri.getRawFragment() == null
                && ("https".equalsIgnoreCase(uri.getScheme())
                || (allowHttp && "http".equalsIgnoreCase(uri.getScheme())));
    }
}
