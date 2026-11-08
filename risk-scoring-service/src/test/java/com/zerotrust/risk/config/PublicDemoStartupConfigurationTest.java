package com.zerotrust.risk.config;

import com.zerotrust.risk.RiskScoringApplication;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.jdbc.autoconfigure.DataSourceProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(OutputCaptureExtension.class)
class PublicDemoStartupConfigurationTest {
    static final String SECRET = "synthetic-only-secret-123456789";
    static final String SCHEMA = "pd_production_risk";
    static final String[] VALID = {
            "PUBLIC_DEMO_MODE=public-demo", "PUBLIC_DEMO_ACADEMIC_READ_ONLY=true",
            "PUBLIC_DEMO_ENVIRONMENT=production", "spring.profiles.active=public-demo",
            "RISK_DB_URL=jdbc:mysql://school-db:3306/" + SCHEMA + "?sslMode=VERIFY_IDENTITY&serverTimezone=UTC",
            "RISK_DB_USERNAME=" + SCHEMA + "_runtime", "RISK_DB_PASSWORD=" + SECRET,
            "RISK_TLS_KEY_STORE=file:/synthetic/never-opened.p12", "RISK_TLS_KEY_STORE_PASSWORD=" + SECRET + "-tls",
            "RISK_TLS_KEY_ALIAS=risk", "RISK_JWT_ISSUER_URI=https://auth.example.invalid/realms/demo",
            "RISK_JWT_JWK_SET_URI=https://auth.example.invalid/realms/demo/protocol/openid-connect/certs",
            "RISK_REDIS_HOST=risk-redis", "RISK_REDIS_PASSWORD=" + SECRET + "-redis",
            "RISK_DEVICE_FINGERPRINT_PEPPER=" + SECRET + "-device", "RISK_AUTH_HISTORY_PEPPER=" + SECRET + "-history"
    };

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withInitializer(context -> {
                new ConfigDataApplicationContextInitializer().initialize(context);
                new PublicDemoStartupInitializer().initialize(context);
            }).withUserConfiguration(MockDatabase.class);

    @Test
    void validEffectivePropertiesStartContextWithMockMetadataOnly() {
        runner.withPropertyValues(VALID).run(context -> {
            assertThat(context).hasNotFailed();
            DataSourceProperties bound = context.getBean(DataSourceProperties.class);
            assertThat(bound.getUsername()).isEqualTo(SCHEMA + "_runtime");
            assertThat(bound.getUrl()).contains("sslMode=VERIFY_IDENTITY");
            assertThat(context.getEnvironment().getProperty("spring.datasource.hikari.read-only")).isEqualTo("false");
            assertThat(context.getEnvironment().getProperty("spring.flyway.enabled")).isEqualTo("false");
            verifyNoInteractions(context.getBean(DataSource.class));
        });
    }

    @Test
    void mountedConfigTreeSecretBindsBeforeValidation(@org.junit.jupiter.api.io.TempDir java.nio.file.Path directory)
            throws java.io.IOException {
        java.nio.file.Files.writeString(directory.resolve("spring.datasource.password"), SECRET);
        String[] withoutEnvSecret = Stream.of(VALID).filter(p -> !p.startsWith("RISK_DB_PASSWORD="))
                .toArray(String[]::new);
        runner.withPropertyValues(withoutEnvSecret)
                .withPropertyValues("spring.config.import=configtree:" + directory.toString().replace('\\', '/') + "/")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(DataSourceProperties.class).getPassword()).isEqualTo(SECRET);
                });
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"RISK_DB_URL", "RISK_DB_USERNAME", "RISK_DB_PASSWORD", "PUBLIC_DEMO_MODE", "PUBLIC_DEMO_ACADEMIC_READ_ONLY"})
    void absentRequiredEnvironmentVariableCannotUseLabFallback(String missing) {
        String[] incomplete = Stream.of(VALID).filter(p -> !p.startsWith(missing + "=")).toArray(String[]::new);
        runner.withPropertyValues(incomplete).run(context -> assertThat(context).hasFailed());
    }

    static Stream<String> rejectedOverrides() {
        return Stream.of(
                "spring.data.redis.password="+SECRET,"server.ssl.key-store-password="+SECRET,
                "risk.security.allowed-client-id=zerotrust-portal-risk-admin", "risk.security.revoke-client-id=zerotrust-risk-caller", "risk.security.audience=zerotrust-api",
                "risk.device-fingerprint.pepper=synthetic-short-marker", "risk.authentication-history.pepper=synthetic-short-marker",
                "spring.datasource.password=                ","spring.datasource.password="+"x".repeat(4097),
                "server.forward-headers-strategy=framework", "server.forward-headers-strategy=native",
                "spring.datasource.url=", "spring.datasource.username=", "spring.datasource.password=",
                "spring.datasource.username=root", "spring.datasource.username=legacy_school",
                "spring.datasource.username=pd_production_risk_migrator",
                "spring.datasource.username=pd_production_risk_provisioner",
                "spring.jpa.hibernate.ddl-auto=update", "spring.jpa.hibernate.ddl-auto=create-drop",
                "spring.jpa.generate-ddl=true", "spring.sql.init.mode=always", "spring.flyway.enabled=true",
                "spring.liquibase.enabled=true", "spring.jpa.show-sql=true",
                "spring.datasource.hikari.read-only=true", "PUBLIC_DEMO_ACADEMIC_READ_ONLY=",
                "PUBLIC_DEMO_ACADEMIC_READ_ONLY=false", "PUBLIC_DEMO_MODE=lab",
                "PUBLIC_DEMO_MODE=publci-demo", "PUBLIC_DEMO_ENVIRONMENT=lab",
                "spring.datasource.password=short", "spring.datasource.password=${UNRESOLVED_SECRET}",
                "spring.datasource.hikari.jdbc-url=jdbc:h2:mem:override",
                "spring.datasource.hikari.username=root", "spring.datasource.hikari.jdbcUrl=jdbc:h2:mem:alias", "spring.datasource.hikari.password=" + SECRET,
                "spring.datasource.hikari.connection-init-sql=INSERT INTO users VALUES (1)",
                "spring.datasource.hikari.data-source-properties.sslMode=DISABLED",
                "spring.datasource.hikari.data-source-properties.allowPublicKeyRetrieval=true",
                "spring.datasource.hikari.data-source-class-name=org.h2.jdbcx.JdbcDataSource",
                "spring.datasource.driver-class-name=org.h2.Driver",
                "spring.datasource.jndi-name=java:comp/env/unsafe",
                "spring.jpa.properties.hibernate.hbm2ddl.auto=update",
                "spring.jpa.properties.jakarta.persistence.schema-generation.database.action=create",
                "spring.flyway.user=migrator", "spring.flyway.password=" + SECRET,
                "risk.security.issuer-uri=http://localhost:8180",
                "server.ssl.enabled=false", "server.ssl.key-store-password=", "risk.security.require-https=false", "spring.data.redis.ssl.enabled=false",
                "spring.data.redis.host=localhost", "spring.data.redis.password=",
                "spring.data.redis.url=redis://localhost:6379",
                "risk.device-fingerprint.pepper=", "risk.authentication-history.pepper=",
                "spring.datasource.url=jdbc:h2:mem:synthetic");
    }

    @ParameterizedTest
    @MethodSource("rejectedOverrides")
    void rejectsUnsafeEffectiveOverridesBeforeDatabaseBeans(String override) {
        java.util.concurrent.atomic.AtomicInteger created = new java.util.concurrent.atomic.AtomicInteger();
        runner.withPropertyValues(VALID).withPropertyValues(override)
                .withBean("initializationProbe", String.class, () -> { created.incrementAndGet(); return "created"; })
                .run(context -> {
            assertThat(context).hasFailed();
            assertThat(created.get()).isZero();
            assertThat(context.getStartupFailure()).hasStackTraceContaining("Public Demo configuration rejected:");
            assertThat(context.getStartupFailure()).hasStackTraceContaining("value redacted")
                    .hasStackTraceContaining("IllegalStateException");
            assertThat(context.getStartupFailure().toString()).doesNotContain(SECRET, "jdbc:mysql:", "jdbc:h2:");
        });
    }

    static Stream<String> insecureJdbcUrls() {
        String prefix = "jdbc:mysql://school-db/" + SCHEMA;
        return Stream.of(prefix, prefix + "?sslMode=PREFERRED", prefix + "?sslMode=REQUIRED",
                prefix + "?sslMode=VERIFY_CA", prefix + "?useSSL=false",
                prefix + "?sslMode=VERIFY_IDENTITY&createDatabaseIfNotExist=true",
                prefix + "?sslMode=VERIFY_IDENTITY&allowPublicKeyRetrieval=true",
                prefix + "?sslMode=VERIFY_IDENTITY&sslMode=DISABLED",
                prefix + "?sslMode=VERIFY_IDENTITY&%73slMode=DISABLED",
                prefix + "?sslMode=VERIFY_IDENTITY&user=root&password=" + SECRET,
                prefix + "?sslMode=VERIFY_IDENTITY&sessionVariables=sql_log_bin=0",
                prefix + "?sslMode=VERIFY_IDENTITY&autoDeserialize=true",
                prefix + "?sslMode=VERIFY_IDENTITY&socketFactory=unsafe.Factory",
                "jdbc:mysql://root:" + SECRET + "@school-db/" + SCHEMA + "?sslMode=VERIFY_IDENTITY",
                "jdbc:mysql://localhost/" + SCHEMA + "?sslMode=VERIFY_IDENTITY",
                "jdbc:mysql://127.0.0.1/" + SCHEMA + "?sslMode=VERIFY_IDENTITY",
                "jdbc:mysql://lab-school/vip_pro?sslMode=VERIFY_IDENTITY",
                "jdbc:mysql://school-db/vip_pro?sslMode=VERIFY_IDENTITY",
                "jdbc:mysql:loadbalance://school-db/" + SCHEMA + "?sslMode=VERIFY_IDENTITY");
    }

    @ParameterizedTest
    @MethodSource("insecureJdbcUrls")
    void rejectsJdbcAlternateOptionsAndLabTargets(String url) {
        runner.withPropertyValues(VALID).withPropertyValues("spring.datasource.url=" + url)
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void currentLabDefaultsStillLoadWithoutProductionLauncherPolicy() {
        runner.withPropertyValues("RISK_DB_PASSWORD=" + SECRET).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(DataSourceProperties.class).getUsername()).isEqualTo("root");
            assertThat(context.getEnvironment().getProperty("spring.jpa.hibernate.ddl-auto")).isEqualTo("validate");
            assertThat(context.getEnvironment().getProperty("spring.flyway.enabled")).isEqualTo("true");
        });
    }

    @Test
    void modeMarkersAloneCannotBypassDatabaseContractWithMissingProfile() {
        runner.withPropertyValues(VALID).withPropertyValues("spring.profiles.active=typo",
                "spring.datasource.username=root").run(context -> assertThat(context).hasFailed());
    }

    @Test
    void canonicalMainRejectsProductionWithAllMarkersAbsent(CapturedOutput output) {
        assertThatThrownBy(() -> RiskScoringApplication.main(new String[]{
                "--spring.profiles.active=prod", "--spring.main.web-application-type=none",
                "--spring.autoconfigure.exclude=org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration,org.springframework.boot.data.redis.autoconfigure.RedisAutoConfiguration",
                "--spring.datasource.password=" + SECRET}))
                .hasMessageContaining("Public Demo configuration rejected:");
        assertThat(output.getAll()).doesNotContain(SECRET);
    }

    @Test
    void canonicalMainRedactsMaliciousUrlAndSecrets(CapturedOutput output) {
        String[] args = Stream.concat(Stream.of(VALID).map(p -> "--" + p), Stream.of(
                "--spring.main.web-application-type=none",
                "--spring.autoconfigure.exclude=org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration,org.springframework.boot.data.redis.autoconfigure.RedisAutoConfiguration",
                "--spring.datasource.url=jdbc:mysql://root:" + SECRET + "@localhost/unsafe"))
                .toArray(String[]::new);
        assertThatThrownBy(() -> RiskScoringApplication.main(args)).hasMessageContaining("value redacted");
        assertThat(output.getAll()).doesNotContain(SECRET, "root:" + SECRET, "jdbc:mysql://root:");
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(DataSourceProperties.class)
    static class MockDatabase {
        @Bean DataSource dataSource() { return mock(DataSource.class); }
    }
}
