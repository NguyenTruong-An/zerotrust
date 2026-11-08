package com.zerotrust.zerotrust.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(PublicDemoProperties.class)
public class PublicDemoConfiguration {
    public PublicDemoConfiguration(PublicDemoProperties properties, Environment environment) {
        if (environment.acceptsProfiles(Profiles.of("public-demo")) && !properties.enabled()) {
            throw new IllegalStateException("The public-demo profile requires PUBLIC_DEMO mode");
        }
    }
}
