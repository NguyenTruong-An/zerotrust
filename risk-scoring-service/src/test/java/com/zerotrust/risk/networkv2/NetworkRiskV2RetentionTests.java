package com.zerotrust.risk.networkv2;

import com.zerotrust.risk.config.NetworkRiskV2Properties;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import java.sql.Timestamp;
import java.time.*;
import java.util.UUID;
import static org.assertj.core.api.Assertions.*;

class NetworkRiskV2RetentionTests {
    private final Instant now = Instant.parse("2026-11-12T12:00:00Z");
    private final NetworkRiskV2Properties properties = new NetworkRiskV2Properties();
    private JdbcTemplate jdbc;
    private NetworkRiskV2Retention retention;
    @BeforeEach void setup() {
        var source = new JdbcDataSource(); source.setURL("jdbc:h2:mem:"+ UUID.randomUUID()+";MODE=MySQL;DB_CLOSE_DELAY=-1");
        jdbc = new JdbcTemplate(source);
        jdbc.execute("CREATE TABLE network_authentication_contexts(event_id VARCHAR(255) PRIMARY KEY,recorded_at TIMESTAMP(6),authenticated_at TIMESTAMP(6))");
        jdbc.execute("CREATE TABLE authentication_success_events(event_id VARCHAR(255) PRIMARY KEY)");
        jdbc.update("INSERT INTO authentication_success_events VALUES('unchanged-parent')");
        retention = new NetworkRiskV2Retention(source, properties, Clock.fixed(now, ZoneOffset.UTC));
    }
    private void row(String id, int recordedDays, int authenticatedDays) {
        jdbc.update("INSERT INTO network_authentication_contexts VALUES(?,?,?)",id,
                Timestamp.from(now.minus(Duration.ofDays(recordedDays))),Timestamp.from(now.minus(Duration.ofDays(authenticatedDays))));
    }
    private void enable() { properties.setMode(NetworkRiskV2Properties.Mode.SHADOW); properties.setRetentionEnabled(true); }
    @Test void defaultsCannotDeleteEvenWhenCalledManually() {
        row("old",31,31); assertThat(retention.purgeBatch()).isZero();
        properties.setRetentionEnabled(true); assertThat(retention.purgeBatch()).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM network_authentication_contexts",Integer.class)).isEqualTo(1);
    }
    @Test void boundedBatchDeletesOnlyOldShadowRowsAndIsIdempotent() {
        enable(); properties.setRetentionBatchSize(2);
        row("old1",31,31); row("old2",32,32); row("old3",33,33);
        row("boundary",30,30); row("new",1,1); row("recently-recorded",1,40); row("recent-auth",40,1);
        assertThat(retention.purgeBatch()).isEqualTo(2);
        assertThat(retention.purgeBatch()).isEqualTo(1);
        assertThat(retention.purgeBatch()).isZero();
        assertThat(jdbc.queryForList("SELECT event_id FROM network_authentication_contexts",String.class))
                .containsExactlyInAnyOrder("boundary","new","recently-recorded","recent-auth");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM authentication_success_events",Integer.class)).isEqualTo(1);
    }
    @Test void invalidRetentionConfigurationCannotShortenHistoryOrEnableDeletionOutsideShadow() {
        try(var factory=jakarta.validation.Validation.buildDefaultValidatorFactory()) {
            var validator=factory.getValidator();
            assertThat(validator.validate(properties)).isEmpty();
            properties.setRetentionDays(29); assertThat(validator.validate(properties)).isNotEmpty();
            properties.setRetentionDays(30); properties.setRetentionEnabled(true);
            assertThat(validator.validate(properties)).isNotEmpty();
            properties.setMode(NetworkRiskV2Properties.Mode.SHADOW); assertThat(validator.validate(properties)).isEmpty();
        }
    }
    @Test void schedulerFailureIsContainedAndDoesNotExposeSqlDetails() {
        var failed=org.mockito.Mockito.mock(NetworkRiskV2Retention.class);
        org.mockito.Mockito.when(failed.purgeBatch()).thenThrow(new IllegalStateException("synthetic-sensitive-detail"));
        assertThatCode(()->new NetworkRiskV2RetentionSchedule(failed).run()).doesNotThrowAnyException();
    }
}
