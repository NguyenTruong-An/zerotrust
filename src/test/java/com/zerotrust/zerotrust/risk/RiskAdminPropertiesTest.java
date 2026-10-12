package com.zerotrust.zerotrust.risk;

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

class RiskAdminPropertiesTest {
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(ValidationAutoConfiguration.class))
            .withUserConfiguration(PropertiesConfiguration.class);

    @Test
    void bindsFiniteDefaultsWithoutRequiringOptionalRiskCredentials() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            RiskAdminProperties properties = context.getBean(RiskAdminProperties.class);
            assertThat(properties.getConnectTimeout()).isEqualTo(Duration.ofSeconds(3));
            assertThat(properties.getReadTimeout()).isEqualTo(Duration.ofSeconds(5));
            assertThat(properties.configured()).isFalse();
        });
    }

    @ParameterizedTest
    @MethodSource("invalidTimeouts")
    void rejectsTimeoutOutsideHttpClientRange(String property, String value) {
        runner.withPropertyValues("app.risk-admin." + property + "=" + value).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasRootCauseInstanceOf(BindValidationException.class);
        });
    }

    @Test
    void acceptsMillisecondBoundaries() {
        runner.withPropertyValues(
                "app.risk-admin.connect-timeout=1ms",
                "app.risk-admin.read-timeout=2147483647ms").run(context -> {
            assertThat(context).hasNotFailed();
            RiskAdminProperties properties = context.getBean(RiskAdminProperties.class);
            assertThat(properties.getConnectTimeout()).isEqualTo(Duration.ofMillis(1));
            assertThat(properties.getReadTimeout()).isEqualTo(Duration.ofMillis(Integer.MAX_VALUE));
        });
    }

    @Test
    void blankTimeoutsKeepFiniteDefaults() {
        runner.withPropertyValues(
                "app.risk-admin.connect-timeout=",
                "app.risk-admin.read-timeout=").run(context -> {
            assertThat(context).hasNotFailed();
            RiskAdminProperties properties = context.getBean(RiskAdminProperties.class);
            assertThat(properties.getConnectTimeout()).isEqualTo(Duration.ofSeconds(3));
            assertThat(properties.getReadTimeout()).isEqualTo(Duration.ofSeconds(5));
        });
    }

    private static Stream<Arguments> invalidTimeouts() {
        return Stream.of("connect-timeout", "read-timeout").flatMap(property ->
                Stream.of("0ms", "-1ms", "1ns", "2147483648ms", "999999999999999999s")
                        .map(value -> Arguments.of(property, value)));
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(RiskAdminProperties.class)
    static class PropertiesConfiguration {
    }
}
