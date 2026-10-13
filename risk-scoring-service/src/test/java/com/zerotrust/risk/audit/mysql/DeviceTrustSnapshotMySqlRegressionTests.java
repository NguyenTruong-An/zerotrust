package com.zerotrust.risk.audit.mysql;

import com.zerotrust.risk.config.DeviceFingerprintProperties;
import com.zerotrust.risk.domain.DeviceRecognitionStatus;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.entity.DeviceStatus;
import com.zerotrust.risk.entity.KnownDeviceEntity;
import com.zerotrust.risk.repository.KnownDeviceRepository;
import com.zerotrust.risk.repository.RedisAuthenticationFailureStore;
import com.zerotrust.risk.service.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.*;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.*;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.*;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.*;
import static org.assertj.core.api.SoftAssertions.assertSoftly;

/** Native QA only; runs against either HEAD or the working tree without audit-only production dependencies. */
@EnabledIfSystemProperty(named="qa.mysql.audit",matches="true")
@SpringBootTest(properties={
        "spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver",
        "spring.datasource.url=jdbc:mysql://127.0.0.1:3308/risk_qa?serverTimezone=UTC",
        "spring.datasource.username=risk_qa","spring.jpa.hibernate.ddl-auto=validate",
        "spring.flyway.clean-disabled=true","spring.jpa.show-sql=true",
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration,org.springframework.boot.autoconfigure.data.redis.RedisReactiveAutoConfiguration,org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration"})
@ActiveProfiles("test")
@ContextConfiguration(initializers=MySqlQaBootstrap.class)
@Import(DeviceTrustSnapshotMySqlRegressionTests.Fixture.class)
class DeviceTrustSnapshotMySqlRegressionTests {
    static final Instant NOW=MySqlQaBootstrap.NOW;
    static final String REQUESTER="qa01c1-admin";
    @Autowired DeviceTrustLifecycle lifecycle;
    @Autowired TrustedDeviceRegistrationService registration;
    @Autowired DeviceRecognitionService recognition;
    @Autowired KnownDeviceRepository devices;
    @Autowired DeviceFingerprintHasher hasher;
    @Autowired JdbcTemplate jdbc;
    @Autowired PlatformTransactionManager transactions;
    @MockitoBean RedisAuthenticationFailureStore redis;

    @DynamicPropertySource static void credential(DynamicPropertyRegistry p) {
        p.add("spring.datasource.password",MySqlQaBootstrap::password);
        p.add("risk.device-fingerprint.pepper",()->"qa-fix03-only-synthetic-device-pepper");
    }
    @TestConfiguration static class Fixture {
        @Bean @Primary Clock snapshotClock() {return Clock.fixed(NOW,ZoneOffset.UTC);}
    }

    // Same schedule and business oracle as the original MySqlSnapshotAuditTests.
    @ParameterizedTest(name="reset snapshot isolation={0}")
    @ValueSource(ints={TransactionDefinition.ISOLATION_REPEATABLE_READ,TransactionDefinition.ISOLATION_READ_COMMITTED})
    void committedRegistrationMustBeRevokedEvenWhenResetJoinsAnExistingSnapshot(int isolation) throws Exception {
        String subject=subject();lifecycle.generation(subject);var operation=UUID.randomUUID();
        CountDownLatch snapshotOpen=new CountDownLatch(1),registered=new CountDownLatch(1);
        ExecutorService pool=Executors.newSingleThreadExecutor();AtomicLong resetConnection=new AtomicLong();
        try {
            Future<?> reset=pool.submit(() -> tx(isolation,() -> {
                resetConnection.set(connectionId());
                assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM known_devices WHERE subject_id=?",Integer.class,subject)).isZero();
                snapshotOpen.countDown();waitFor(registered);
                lifecycle.revoke(subject,operation,REQUESTER);
                assertThat(connectionId()).isEqualTo(resetConnection.get());return null;
            }));
            waitFor(snapshotOpen);registration.trustAfterMfa(subject,"committed-before-reset",0);registered.countDown();
            reset.get(25,TimeUnit.SECONDS);
            var afterReset=device(subject,"committed-before-reset");
            int count=auditCount(operation);
            assertThat(lifecycle.snapshot(subject).generation()).isEqualTo(1);
            assertThat(lifecycle.snapshot(subject).resetPending()).isTrue();
            lifecycle.complete(subject,operation,REQUESTER);
            var result=recognize(subject,"committed-before-reset");
            System.out.printf("FIX03 SNAPSHOT isolation=%d connection=%d status=%s audit=%d recognition=%s%n",isolation,resetConnection.get(),afterReset.getStatus(),count,result);
            assertSoftly(s -> {
                s.assertThat(afterReset.getStatus()).isEqualTo(DeviceStatus.REVOKED);
                s.assertThat(count).isEqualTo(1);
                s.assertThat(result).isEqualTo(DeviceRecognitionStatus.REAUTHENTICATION_REQUIRED);
            });
        } finally {registered.countDown();pool.shutdownNow();assertThat(pool.awaitTermination(25,TimeUnit.SECONDS)).isTrue();}
    }

    @ParameterizedTest(name="preloaded SECURITY isolation={0}")
    @ValueSource(ints={TransactionDefinition.ISOLATION_REPEATABLE_READ,TransactionDefinition.ISOLATION_READ_COMMITTED})
    void preloadedEntityMustRefreshCommittedSecurityRevocationWithoutChangingItsReasonOrVersion(int isolation) throws Exception {
        String subject=subject();registration.trustAfterMfa(subject,"security",0);UUID operation=UUID.randomUUID();
        CountDownLatch loaded=new CountDownLatch(1),secured=new CountDownLatch(1);
        ExecutorService pool=Executors.newSingleThreadExecutor();
        try {
            Future<?> reset=pool.submit(() -> tx(isolation,() -> {
                KnownDeviceEntity cached=device(subject,"security");
                assertThat(cached.getStatus()).isEqualTo(DeviceStatus.TRUSTED);
                loaded.countDown();waitFor(secured);
                lifecycle.revoke(subject,operation,REQUESTER);
                assertThat(cached.getStatus()).isEqualTo(DeviceStatus.REVOKED);
                assertThat(cached.getRevocationReason()).isEqualTo("SECURITY");
                assertThat(cached.getVersion()).isEqualTo(1);return null;
            }));
            waitFor(loaded);tx(isolation,()->{device(subject,"security").revoke(NOW);return null;});secured.countDown();
            reset.get(25,TimeUnit.SECONDS);
            assertThat(auditCount(operation)).isZero();
            assertThat(lifecycle.snapshot(subject)).isEqualTo(new DeviceTrustLifecycle.Snapshot(1,true));
            lifecycle.complete(subject,operation,REQUESTER);
            assertThat(recognize(subject,"security")).isEqualTo(DeviceRecognitionStatus.REVOKED);
            assertThat(device(subject,"security").getRevocationReason()).isEqualTo("SECURITY");
            assertThat(device(subject,"security").getVersion()).isEqualTo(1);
        } finally {secured.countDown();pool.shutdownNow();assertThat(pool.awaitTermination(25,TimeUnit.SECONDS)).isTrue();}
    }

    @Test void refreshingDevicesMustPreserveTheCallersPendingChanges() {
        String subject=subject();registration.trustAfterMfa(subject,"own-change",0);UUID operation=UUID.randomUUID();
        tx(TransactionDefinition.ISOLATION_REPEATABLE_READ,()->{
            device(subject,"own-change").markSeen(NOW.plusSeconds(1));
            lifecycle.revoke(subject,operation,REQUESTER);return null;
        });
        assertThat(device(subject,"own-change").getLastSeenAt()).isEqualTo(NOW.plusSeconds(1));
        assertThat(device(subject,"own-change").getStatus()).isEqualTo(DeviceStatus.REVOKED);
        assertThat(auditCount(operation)).isEqualTo(1);
    }

    @Test void invalidRevocationTimeMustStillRollBackGenerationDevicesAndAudit() {
        String subject=subject();lifecycle.generation(subject);UUID operation=UUID.randomUUID();
        KnownDeviceEntity future=new KnownDeviceEntity(subject,hasher.hash(subject,"future"),NOW.plusSeconds(1));
        future.trust(NOW.plusSeconds(1));devices.saveAndFlush(future);
        assertThatThrownBy(()->lifecycle.revoke(subject,operation,REQUESTER)).isInstanceOf(IllegalArgumentException.class);
        assertThat(lifecycle.snapshot(subject)).isEqualTo(new DeviceTrustLifecycle.Snapshot(0,false));
        assertThat(device(subject,"future").getStatus()).isEqualTo(DeviceStatus.TRUSTED);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM device_trust_revocations WHERE operation_id=?",Integer.class,operation.toString())).isZero();
    }

    String subject() {
        String value=UUID.randomUUID().toString();
        jdbc.update("INSERT INTO qa01c1_fixture_manifest(subject_id,run_id,owner) VALUES(?,?,'01C1')",value,MySqlQaBootstrap.RUN);
        return value;
    }
    KnownDeviceEntity device(String subject,String identifier) {return devices.findBySubjectIdAndDeviceFingerprintHash(subject,hasher.hash(subject,identifier)).orElseThrow();}
    int auditCount(UUID operation) {return jdbc.queryForObject("SELECT revoked_count FROM device_trust_revocations WHERE operation_id=?",Integer.class,operation.toString());}
    long connectionId() {return jdbc.queryForObject("SELECT CONNECTION_ID()",Long.class);}
    <T> T tx(int isolation,Supplier<T> work) {
        TransactionTemplate t=new TransactionTemplate(transactions);t.setIsolationLevel(isolation);return t.execute(s->work.get());
    }
    DeviceRecognitionStatus recognize(String subject,String identifier) {
        return recognition.recognize(new LoginContext(subject,"qa-session","qa-client","192.0.2.1",null,identifier,NOW)).status();
    }
    static void waitFor(CountDownLatch latch) {
        try {if(!latch.await(20,TimeUnit.SECONDS)) throw new AssertionError("checkpoint timeout");}
        catch(InterruptedException e) {Thread.currentThread().interrupt();throw new AssertionError(e);}
    }
}
