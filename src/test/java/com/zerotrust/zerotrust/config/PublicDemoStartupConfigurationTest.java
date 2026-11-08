package com.zerotrust.zerotrust.config;

import com.zerotrust.zerotrust.ZerotrustApplication;
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
    static final String SCHEMA = "pd_production_school";
    static final String[] VALID = {
            "PUBLIC_DEMO_MODE=public-demo", "PUBLIC_DEMO_ACADEMIC_READ_ONLY=true",
            "PUBLIC_DEMO_ENVIRONMENT=production", "spring.profiles.active=public-demo",
            "DB_URL=jdbc:mysql://school-db:3306/" + SCHEMA + "?sslMode=VERIFY_IDENTITY&serverTimezone=UTC",
            "DB_USERNAME=" + SCHEMA + "_runtime", "DB_PASSWORD=" + SECRET,
            "KEYCLOAK_ISSUER_URI=https://auth.example.invalid/realms/demo",
            "KEYCLOAK_JWK_SET_URI=https://auth.example.invalid/realms/demo/protocol/openid-connect/certs",
            "KEYCLOAK_URL=https://auth.example.invalid", "KEYCLOAK_REALM=demo",
            "KEYCLOAK_ADMIN_CLIENT_ID=demo-provisioner", "KEYCLOAK_ADMIN_CLIENT_SECRET=" + SECRET + "-identity",
            "CORS_ALLOWED_ORIGINS=https://portal.example.invalid",
            "PORTAL_RISK_BASE_URL=https://risk.internal", "PORTAL_RISK_TOKEN_URI=https://auth.example.invalid/token",
            "PORTAL_RISK_CLIENT_SECRET=" + SECRET + "-revoke"
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
            assertThat(context).hasSingleBean(PublicDemoSchoolDatabaseVerifier.class);
            verify(context.getBean(DataSource.class)).getConnection();
        });
    }

    @Test
    void mountedConfigTreeSecretBindsBeforeValidation(@org.junit.jupiter.api.io.TempDir java.nio.file.Path directory)
            throws java.io.IOException {
        java.nio.file.Files.writeString(directory.resolve("spring.datasource.password"), SECRET);
        String[] withoutEnvSecret = Stream.of(VALID).filter(p -> !p.startsWith("DB_PASSWORD="))
                .toArray(String[]::new);
        runner.withPropertyValues(withoutEnvSecret)
                .withPropertyValues("spring.config.import=configtree:" + directory.toString().replace('\\', '/') + "/")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(DataSourceProperties.class).getPassword()).isEqualTo(SECRET);
                });
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"DB_URL", "DB_USERNAME", "DB_PASSWORD", "PUBLIC_DEMO_MODE", "PUBLIC_DEMO_ACADEMIC_READ_ONLY"})
    void absentRequiredEnvironmentVariableCannotUseLabFallback(String missing) {
        String[] incomplete = Stream.of(VALID).filter(p -> !p.startsWith(missing + "=")).toArray(String[]::new);
        runner.withPropertyValues(incomplete).run(context -> assertThat(context).hasFailed());
    }

    static Stream<String> rejectedOverrides() {
        return Stream.of(
                "keycloak.admin.client-secret="+SECRET, "app.risk-admin.client-secret="+SECRET,
                "app.risk-admin.client-id=zerotrust-risk-caller", "keycloak.admin.client-id=zerotrust-portal-risk-admin",
                "spring.datasource.password=                ", "spring.datasource.password="+"x".repeat(4097),
                "server.forward-headers-strategy=framework", "server.forward-headers-strategy=native",
                "spring.datasource.url=", "spring.datasource.username=", "spring.datasource.password=",
                "spring.datasource.username=root", "spring.datasource.username=legacy_school",
                "spring.datasource.username=pd_production_school_migrator",
                "spring.datasource.username=pd_production_school_provisioner",
                "spring.jpa.hibernate.ddl-auto=update", "spring.jpa.hibernate.ddl-auto=create-drop",
                "spring.jpa.generate-ddl=true", "spring.sql.init.mode=always", "spring.flyway.enabled=true",
                "spring.liquibase.enabled=true", "spring.jpa.show-sql=true",
                "spring.datasource.hikari.read-only=false", "PUBLIC_DEMO_ACADEMIC_READ_ONLY=",
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
                "keycloak.admin.client-secret=", "app.risk-admin.client-secret=",
                "keycloak.admin.server-url=http://localhost:8180",
                "spring.security.oauth2.resourceserver.jwt.issuer-uri=http://auth.internal/realm",
                "app.security.cors.allowed-origins=*", "app.risk-admin.allow-http=true",
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
        runner.withPropertyValues("DB_PASSWORD=" + SECRET).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(DataSourceProperties.class).getUsername()).isEqualTo("root");
            assertThat(context.getEnvironment().getProperty("spring.jpa.hibernate.ddl-auto")).isEqualTo("update");
            assertThat(context).doesNotHaveBean(PublicDemoSchoolDatabaseVerifier.class);
        });
    }

    @Test
    void modeMarkersAloneCannotBypassDatabaseContractWithMissingProfile() {
        runner.withPropertyValues(VALID).withPropertyValues("spring.profiles.active=typo",
                "spring.datasource.username=root").run(context -> assertThat(context).hasFailed());
    }

    @Test
    void canonicalMainRejectsProductionWithAllMarkersAbsent(CapturedOutput output) {
        assertThatThrownBy(() -> ZerotrustApplication.main(new String[]{
                "--spring.profiles.active=prod", "--spring.main.web-application-type=none",
                "--spring.autoconfigure.exclude=org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration,org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration",
                "--spring.datasource.password=" + SECRET}))
                .hasMessageContaining("Public Demo configuration rejected:");
        assertThat(output.getAll()).doesNotContain(SECRET);
    }

    @Test
    void canonicalMainRedactsMaliciousUrlAndSecrets(CapturedOutput output) {
        String[] args = Stream.concat(Stream.of(VALID).map(p -> "--" + p), Stream.of(
                "--spring.main.web-application-type=none",
                "--spring.autoconfigure.exclude=org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration,org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration",
                "--spring.datasource.url=jdbc:mysql://root:" + SECRET + "@localhost/unsafe"))
                .toArray(String[]::new);
        assertThatThrownBy(() -> ZerotrustApplication.main(args)).hasMessageContaining("value redacted");
        assertThat(output.getAll()).doesNotContain(SECRET, "root:" + SECRET, "jdbc:mysql://root:");
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(DataSourceProperties.class)
    static class MockDatabase {
        @Bean DataSource dataSource() throws Exception {
            DataSource source = mock(DataSource.class);
            Connection connection = mock(Connection.class);
            Statement statement = mock(Statement.class);
            DatabaseMetaData metadata = mock(DatabaseMetaData.class);
            when(source.getConnection()).thenReturn(connection);
            when(connection.getCatalog()).thenReturn(SCHEMA);
            when(connection.getMetaData()).thenReturn(metadata);
            when(metadata.getDatabaseProductName()).thenReturn("MySQL");
            when(connection.createStatement()).thenReturn(statement);
            ResultSet account = mock(ResultSet.class);
            when(account.next()).thenReturn(true, false);
            when(account.getString(1)).thenReturn(SCHEMA + "_runtime@%");
            when(statement.executeQuery("SELECT CURRENT_USER()")).thenReturn(account);
            ResultSet tls = mock(ResultSet.class);
            when(tls.next()).thenReturn(true, false); when(tls.getString(2)).thenReturn("TLS_AES_256_GCM_SHA384");
            when(statement.executeQuery("SHOW SESSION STATUS LIKE 'Ssl_cipher'")).thenReturn(tls);
            ResultSet grants = mock(ResultSet.class);
            when(grants.next()).thenReturn(true, true, true, true, true, false);
            when(grants.getString(1)).thenReturn(
                    grant("users"), grant("students"), grant("student_classes"), grant("subjects"), grant("scores"));
            when(statement.executeQuery("SHOW GRANTS FOR CURRENT_USER")).thenReturn(grants);
            return source;
        }
        static String grant(String table) { return "GRANT SELECT ON `" + SCHEMA + "`.`" + table + "` TO 'pd_production_school_runtime'@'%'"; }
    }
}
