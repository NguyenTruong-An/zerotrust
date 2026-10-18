package com.zerotrust.risk.service;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.jdbc.core.JdbcTemplate;
import com.zerotrust.risk.repository.KnownDeviceRepository;
import com.zerotrust.risk.repository.RedisAuthenticationFailureStore;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import java.sql.Timestamp;
import java.util.UUID;
import static org.assertj.core.api.Assertions.*;

/** Only selected in the separate exact-BASE source snapshot; characterization of original failed business request. */
@EnabledIfSystemProperty(named="postfix03b.native",matches="APPROVED")
@EnabledIfSystemProperty(named="postfix03b.sourceScope",matches="BASELINE")
@SpringBootTest(properties={"spring.datasource.url=${PF03B_MYSQL_URL}","spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver",
        "spring.datasource.username=pf03b_app","spring.datasource.password=${PF03B_MYSQL_PASSWORD}","spring.jpa.hibernate.ddl-auto=validate","spring.flyway.enabled=false",
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration,org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration"})
@ActiveProfiles("test")
@ContextConfiguration(initializers=TimestampMySqlSupport.class)
@Import(TimestampLifecyclePrecisionContract.TimeConfig.class)
class TimestampLifecycleBaselineMySqlTests {
    @Autowired TrustedDeviceRegistrationService registration;
    @Autowired DeviceTrustLifecycle lifecycle;
    @Autowired KnownDeviceRepository devices;
    @Autowired JdbcTemplate jdbc;
    @MockitoBean RedisAuthenticationFailureStore redis;
    @Test void originalHalfUpClockRejectionKeepsTransactionConsistent() throws Exception {
        TimestampMySqlSupport.before();
        try {
            String s="pf03b-"+System.getProperty("postfix03b.runUUID")+"-"+UUID.randomUUID();String d="device-"+UUID.randomUUID();
            TimestampMySqlSupport.NOW.set(TimestampLifecyclePrecisionContract.at(123456789));registration.trustAfterMfa(s,d,0);
            assertThat(jdbc.queryForObject("SELECT first_seen_at FROM known_devices WHERE subject_id=?",Timestamp.class,s).toInstant()).isEqualTo(TimestampLifecyclePrecisionContract.at(123457000));
            assertThatThrownBy(()->lifecycle.revoke(s,UUID.randomUUID(),"Admin")).isInstanceOf(IllegalArgumentException.class).hasMessage("revokedAt must not be before firstSeenAt");
            assertThat(lifecycle.snapshot(s)).isEqualTo(new DeviceTrustLifecycle.Snapshot(0,false));
            assertThat(devices.findAllBySubjectId(s)).singleElement().extracting(x->x.getStatus().name()).isEqualTo("TRUSTED");
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM device_trust_revocations WHERE subject_id=?",Long.class,s)).isZero();
        } finally {TimestampMySqlSupport.after();}
    }
}
