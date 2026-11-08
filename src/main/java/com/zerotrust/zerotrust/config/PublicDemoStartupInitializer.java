package com.zerotrust.zerotrust.config;

import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.core.env.ConfigurableEnvironment;

import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/** Canonical executable entry point: validate effective ConfigData before any beans or DB I/O.
 * Test slices deliberately exercise the separate PD-02-01 filter without this production launcher.
 * No test-profile/H2 escape hatch is accepted by this initializer.
 */
public final class PublicDemoStartupInitializer
        implements ApplicationContextInitializer<ConfigurableApplicationContext> {

    @Override
    public void initialize(ConfigurableApplicationContext context) {
        ConfigurableEnvironment env = context.getEnvironment();
        boolean production = Arrays.stream(env.getActiveProfiles())
                .anyMatch(p -> Set.of("prod", "production", "public-demo").contains(p));
        String mode = value(env, "app.public-demo.mode");
        String flag = value(env, "app.public-demo.academic-read-only");
        if (!production && (mode.isBlank() || mode.equalsIgnoreCase("lab")) && flag.isBlank()) {
            return; // Existing local/Lab configuration is intentionally unchanged.
        }
        require("public-demo".equals(mode), "app.public-demo.mode");
        exact(env, "app.public-demo.academic-read-only", "true");
        exact(env, "server.forward-headers-strategy", "none");
        String stage = value(env, "app.public-demo.environment");
        require(Set.of("staging", "production").contains(stage), "app.public-demo.environment");
        String schema = "pd_" + stage + "_school";
        exact(env, "spring.datasource.username", schema + "_runtime");
        secret(env, "spring.datasource.password");
        validateJdbc(value(env, "spring.datasource.url"), schema);
        exact(env, "spring.jpa.hibernate.ddl-auto", "validate");
        exact(env, "spring.jpa.generate-ddl", "false");
        exact(env, "spring.sql.init.mode", "never");
        exact(env, "spring.flyway.enabled", "false");
        exact(env, "spring.liquibase.enabled", "false");
        exact(env, "spring.jpa.show-sql", "false");
        exact(env, "spring.datasource.hikari.read-only", "true");
        // Alternative connection channels and Hibernate overrides could undo the checked policy.
        for (String key : Set.of("spring.datasource.jndi-name", "spring.datasource.type",
                "spring.datasource.hikari.jdbc-url", "spring.datasource.hikari.username",
                "spring.datasource.hikari.password", "spring.datasource.hikari.data-source-class-name",
                "spring.datasource.hikari.connection-init-sql", "spring.datasource.hikari.schema",
                "spring.datasource.hikari.catalog", "spring.datasource.hikari.data-source-j-n-d-i")) {
            require(value(env, key).isBlank(), key);
        }
        String driver = value(env, "spring.datasource.driver-class-name");
        require(driver.isBlank() || driver.equals("com.mysql.cj.jdbc.Driver"), "spring.datasource.driver-class-name");
        rejectMap(env, "spring.jpa.properties");
        rejectMap(env, "spring.datasource.hikari.data-source-properties");
        rejectMap(env, "spring.datasource.hikari");
        rejectMap(env, "spring.flyway");
        rejectMap(env, "spring.liquibase");
        https(env, "spring.security.oauth2.resourceserver.jwt.issuer-uri");
        https(env, "spring.security.oauth2.resourceserver.jwt.jwk-set-uri");
        https(env, "keycloak.admin.server-url");
        nonblank(env, "keycloak.admin.realm");
        nonblank(env, "keycloak.admin.client-id");
        secret(env, "keycloak.admin.client-secret");
        https(env, "app.risk-admin.base-url");
        https(env, "app.risk-admin.token-uri");
        exact(env, "app.risk-admin.allow-http", "false");
        secret(env, "app.risk-admin.client-secret");
        exact(env,"app.risk-admin.client-id","zerotrust-portal-risk-admin");
        require(!Set.of("zerotrust-spa","zerotrust-risk-caller","zerotrust-portal-risk-admin","admin-cli").contains(value(env,"keycloak.admin.client-id")),"keycloak.admin.client-id");
        distinctSecrets(env, "spring.datasource.password", "keycloak.admin.client-secret", "app.risk-admin.client-secret");
        for (String origin : value(env, "app.security.cors.allowed-origins").split(",", -1)) {
            require(secureUri(origin.trim()), "app.security.cors.allowed-origins");
        }
        registerSchoolVerifier(context, schema);
    }

    private static void registerSchoolVerifier(ConfigurableApplicationContext context, String schema) {
        context.addBeanFactoryPostProcessor(factory -> {
            RootBeanDefinition definition = new RootBeanDefinition(PublicDemoSchoolDatabaseVerifier.class);
            definition.getConstructorArgumentValues().addIndexedArgumentValue(0, new RuntimeBeanReference("dataSource"));
            definition.getConstructorArgumentValues().addIndexedArgumentValue(1, schema);
            ((BeanDefinitionRegistry) factory).registerBeanDefinition("publicDemoSchoolDatabaseVerifier", definition);
        });
    }

    static void validateJdbc(String url, String schema) {
        String key = "spring.datasource.url";
        try {
            require(url.startsWith("jdbc:mysql://"), key);
            URI uri = URI.create(url.substring(5));
            require(nonLabHost(uri.getHost()) && uri.getUserInfo() == null && uri.getFragment() == null,
                    key);
            require(uri.getPort() == -1 || uri.getPort() > 0 && uri.getPort() <= 65535, key);
            require(("/" + schema).equals(uri.getRawPath()), key);
            Set<String> seen = new HashSet<>();
            boolean tls = false;
            for (String part : uri.getRawQuery().split("&", -1)) {
                String[] pair = part.split("=", -1);
                require(pair.length == 2 && seen.add(pair[0]), key);
                switch (pair[0]) {
                    case "sslMode" -> { require(pair[1].equals("VERIFY_IDENTITY"), key); tls = true; }
                    case "serverTimezone" -> require(pair[1].equals("UTC"), key);
                    case "characterEncoding" -> require(pair[1].equals("UTF-8"), key);
                    case "connectTimeout", "socketTimeout" -> require(pair[1].matches("[1-9][0-9]{0,5}"), key);
                    default -> require(false, key); // No credentials, legacy TLS, custom socket or seed options.
                }
            }
            require(tls, key);
        } catch (RuntimeException ignored) {
            throw invalid(key); // Never chain parser errors that may contain URL credentials.
        }
    }

    private static void rejectMap(ConfigurableEnvironment env, String prefix) {
        try {
            Map<String, String> entries = Binder.get(env).bind(prefix, Bindable.mapOf(String.class, String.class))
                    .orElse(Map.of());
            Set<String> allowed = switch (prefix) {
                case "spring.jpa.properties" -> Set.of("hibernate.format_sql");
                case "spring.flyway", "spring.liquibase" -> Set.of("enabled", "locations");
                case "spring.datasource.hikari" -> Set.of("read-only", "maximum-pool-size", "minimum-idle",
                        "connection-timeout", "validation-timeout", "idle-timeout", "max-lifetime", "pool-name");
                // Trust material belongs in the JVM truststore, never in credential-bearing URL options.
                default -> Set.of();
            };
            require(allowed.containsAll(entries.keySet()), prefix);
        } catch (RuntimeException ignored) {
            throw invalid(prefix);
        }
    }

    private static boolean nonLabHost(String host) {
        return host != null && host.matches("[A-Za-z0-9][A-Za-z0-9.-]*")
                && !host.equalsIgnoreCase("localhost") && !host.startsWith("127.")
                && !host.equals("0.0.0.0") && !host.toLowerCase(java.util.Locale.ROOT).contains("lab");
    }

    private static boolean secureUri(String text) {
        try {
            URI uri = URI.create(text);
            return "https".equals(uri.getScheme()) && nonLabHost(uri.getHost())
                    && uri.getUserInfo() == null && uri.getFragment() == null && uri.getQuery() == null;
        } catch (RuntimeException ignored) { return false; }
    }

    private static void https(ConfigurableEnvironment env, String key) { require(secureUri(value(env, key)), key); }
    private static void exact(ConfigurableEnvironment env, String key, String expected) {
        require(expected.equals(value(env, key)), key);
    }
    private static void nonblank(ConfigurableEnvironment env, String key) { require(!value(env, key).isBlank(), key); }
    private static void secret(ConfigurableEnvironment env, String key) {
        String secret=value(env,key);require(secret.length()>=16 && secret.length()<=4096 && !secret.isBlank()
                && secret.chars().noneMatch(Character::isISOControl),key);
    }
    private static void distinctSecrets(ConfigurableEnvironment env,String... keys){
        Set<String> secrets=new HashSet<>();for(String key:keys)require(secrets.add(value(env,key)),"distinct service secrets");
    }
    private static String value(ConfigurableEnvironment env, String key) {
        try {
            String value = env.getProperty(key, "");
            require(!value.contains("${"), key);
            return value;
        } catch (RuntimeException ignored) { throw invalid(key); }
    }
    private static void require(boolean valid, String key) { if (!valid) throw invalid(key); }
    private static IllegalStateException invalid(String key) {
        return new IllegalStateException("Public Demo configuration rejected: " + key + " (value redacted)");
    }
}
