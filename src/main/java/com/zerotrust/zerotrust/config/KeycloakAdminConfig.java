package com.zerotrust.zerotrust.config;

import org.jboss.resteasy.client.jaxrs.internal.ResteasyClientBuilderImpl;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.JacksonProvider;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableConfigurationProperties(KeycloakAdminProperties.class)
public class KeycloakAdminConfig {

    @Bean(destroyMethod = "close")
    public Keycloak keycloakAdminClient(KeycloakAdminProperties properties) {
        var restClient = new ResteasyClientBuilderImpl()
                .connectionPoolSize(properties.connectionPoolSize())
                .connectTimeout(properties.connectTimeout().toMillis(), TimeUnit.MILLISECONDS)
                .readTimeout(properties.readTimeout().toMillis(), TimeUnit.MILLISECONDS)
                .build()
                .register(JacksonProvider.class, 100);

        Keycloak keycloak = KeycloakBuilder.builder()
                .serverUrl(properties.serverUrl())
                .realm(properties.realm())
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .clientId(properties.clientId())
                .clientSecret(properties.clientSecret())
                .resteasyClient(restClient)
                .build();
        keycloak.tokenManager().setMinTokenValidity(properties.minTokenValiditySeconds());
        return keycloak;
    }
}
