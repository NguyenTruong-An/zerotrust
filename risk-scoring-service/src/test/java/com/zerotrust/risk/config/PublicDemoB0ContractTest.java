package com.zerotrust.risk.config;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.validation.autoconfigure.ValidationAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class PublicDemoB0ContractTest {
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withInitializer(context -> {
                new ConfigDataApplicationContextInitializer().initialize(context);
                new PublicDemoStartupInitializer().initialize(context);
            }).withConfiguration(AutoConfigurations.of(ValidationAutoConfiguration.class))
            .withUserConfiguration(PublicDemoStartupConfigurationTest.MockDatabase.class, PolicyBinding.class)
            .withPropertyValues(PublicDemoStartupConfigurationTest.VALID);

    @ParameterizedTest
    @ValueSource(strings = {"RISK_SCORING_MODEL=CONTINUOUS_B1", "RISK_WEIGHT_DEVICE=0.20",
            "RISK_WEIGHT_NETWORK=0.30", "RISK_WEIGHT_TEMPORAL=0.24", "RISK_WEIGHT_AUTHENTICATION_HISTORY=0.26",
            "RISK_THRESHOLD_MEDIUM_MINIMUM=39", "RISK_THRESHOLD_HIGH_MINIMUM=74"})
    void publicDemoCannotOverrideTheApprovedB0Policy(String override) {
        runner.withPropertyValues(override).run(context -> assertThat(context).hasFailed());
    }

    @ParameterizedTest
    @ValueSource(strings = {"RISK_WEIGHT_DEVICE=0.2500", "RISK_THRESHOLD_MEDIUM_MINIMUM=40.00",
            "RISK_THRESHOLD_HIGH_MINIMUM=75.00"})
    void equivalentDecimalRepresentationsKeepB0Valid(String override) {
        runner.withPropertyValues(override).run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void validWeightSumDoesNotAuthorizeAChangedPublicDemoPolicy() {
        runner.withPropertyValues("RISK_WEIGHT_DEVICE=0.20", "RISK_WEIGHT_NETWORK=0.30")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void generalLabPolicyStillAllowsResearchSettingsWithValidWeightSum() {
        new ApplicationContextRunner().withInitializer(new ConfigDataApplicationContextInitializer())
                .withConfiguration(AutoConfigurations.of(ValidationAutoConfiguration.class))
                .withUserConfiguration(PolicyBinding.class)
                .withPropertyValues("RISK_SCORING_MODEL=CONTINUOUS_B1", "RISK_WEIGHT_DEVICE=0.20", "RISK_WEIGHT_NETWORK=0.30")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(RiskPolicyProperties.class).getWeights().getDevice()).isEqualByComparingTo("0.20");
                });
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(RiskPolicyProperties.class)
    static class PolicyBinding { }
}
