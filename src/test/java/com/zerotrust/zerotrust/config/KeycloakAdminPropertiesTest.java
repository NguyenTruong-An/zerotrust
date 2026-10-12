package com.zerotrust.zerotrust.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.validation.ValidationAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.validation.BindValidationException;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class KeycloakAdminPropertiesTest {
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(ValidationAutoConfiguration.class))
            .withUserConfiguration(PropertiesConfiguration.class)
            .withPropertyValues(
                    "keycloak.admin.server-url=http://localhost:8180",
                    "keycloak.admin.realm=test-realm",
                    "keycloak.admin.client-id=test-client",
                    "keycloak.admin.client-secret=test-only-secret");

    @Test
    void bindsFiniteDefaults() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            KeycloakAdminProperties properties = context.getBean(KeycloakAdminProperties.class);
            assertThat(properties.connectTimeout()).isEqualTo(Duration.ofSeconds(3));
            assertThat(properties.readTimeout()).isEqualTo(Duration.ofSeconds(5));
            assertThat(properties.connectionCheckoutTimeout()).isEqualTo(Duration.ofSeconds(3));
        });
    }

    @ParameterizedTest
    @MethodSource("invalidTimeouts")
    void rejectsTimeoutOutsideHttpClientRange(String property, String value) {
        runner.withPropertyValues("keycloak.admin." + property + "=" + value).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasRootCauseInstanceOf(BindValidationException.class);
        });
    }

    @Test
    void acceptsMillisecondBoundaries() {
        runner.withPropertyValues(
                "keycloak.admin.connect-timeout=1ms",
                "keycloak.admin.read-timeout=2147483647ms",
                "keycloak.admin.connection-checkout-timeout=1ms").run(context -> {
            assertThat(context).hasNotFailed();
            KeycloakAdminProperties properties = context.getBean(KeycloakAdminProperties.class);
            assertThat(properties.connectTimeout()).isEqualTo(Duration.ofMillis(1));
            assertThat(properties.readTimeout()).isEqualTo(Duration.ofMillis(Integer.MAX_VALUE));
            assertThat(properties.connectionCheckoutTimeout()).isEqualTo(Duration.ofMillis(1));
        });
    }

    @Test
    void acceptsUpperBoundaryForConnectionCheckoutTimeout() {
        runner.withPropertyValues("keycloak.admin.connection-checkout-timeout=2147483647ms").run(context -> {
            assertThat(context).hasNotFailed();
            KeycloakAdminProperties properties = context.getBean(KeycloakAdminProperties.class);
            assertThat(properties.connectionCheckoutTimeout()).isEqualTo(Duration.ofMillis(Integer.MAX_VALUE));
        });
    }

    private static Stream<Arguments> invalidTimeouts() {
        return Stream.of("connect-timeout", "read-timeout", "connection-checkout-timeout").flatMap(property ->
                Stream.of("0ms", "-1ms", "1ns", "2147483648ms", "999999999999999999s")
                        .map(value -> Arguments.of(property, value)));
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(KeycloakAdminProperties.class)
    static class PropertiesConfiguration {
    }
}
