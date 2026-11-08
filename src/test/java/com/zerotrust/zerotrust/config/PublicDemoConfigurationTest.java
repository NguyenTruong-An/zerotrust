package com.zerotrust.zerotrust.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.validation.autoconfigure.ValidationAutoConfiguration;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class PublicDemoConfigurationTest {
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withInitializer(new ConfigDataApplicationContextInitializer())
            .withConfiguration(AutoConfigurations.of(ValidationAutoConfiguration.class))
            .withUserConfiguration(PublicDemoConfiguration.class);

    @Test
    void defaultLabIsUnchanged() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(PublicDemoProperties.class).enabled()).isFalse();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "public-demo", "publci-demo"})
    void explicitDeploymentMarkersProtectEvenMissingOrMisspelledProfile(String profile) {
        runner.withPropertyValues("spring.profiles.active=" + profile,
                "PUBLIC_DEMO_MODE=public-demo", "PUBLIC_DEMO_ACADEMIC_READ_ONLY=true")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(PublicDemoProperties.class).enabled()).isTrue();
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "false", "yes", "TRUE", "invalid"})
    void publicDemoRequiresAnExplicitLiteralTrueFlag(String flag) {
        runner.withPropertyValues("PUBLIC_DEMO_MODE=public-demo", "PUBLIC_DEMO_ACADEMIC_READ_ONLY=" + flag)
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void missingFlagCannotFallBackToCrud() {
        runner.withPropertyValues("PUBLIC_DEMO_MODE=public-demo")
                .run(context -> assertThat(context).hasFailed());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "publci-demo", "false", "production"})
    void invalidModeCannotFallBackToLab(String mode) {
        runner.withPropertyValues("PUBLIC_DEMO_MODE=" + mode, "PUBLIC_DEMO_ACADEMIC_READ_ONLY=true")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void orphanReadOnlyFlagCannotSilentlyRunLab() {
        runner.withPropertyValues("PUBLIC_DEMO_ACADEMIC_READ_ONLY=true")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void publicDemoProfileRequiresModeVariable() {
        runner.withPropertyValues("spring.profiles.active=public-demo", "PUBLIC_DEMO_ACADEMIC_READ_ONLY=true")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void publicDemoProfileRequiresReadOnlyVariable() {
        runner.withPropertyValues("spring.profiles.active=public-demo", "PUBLIC_DEMO_MODE=public-demo")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void publicDemoProfileCannotBeOverriddenToLab() {
        runner.withPropertyValues("spring.profiles.active=public-demo", "PUBLIC_DEMO_MODE=lab")
                .run(context -> assertThat(context).hasFailed());
    }
}
