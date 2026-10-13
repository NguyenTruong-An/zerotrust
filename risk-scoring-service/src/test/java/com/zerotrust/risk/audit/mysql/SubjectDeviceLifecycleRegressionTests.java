package com.zerotrust.risk.audit.mysql;

import com.zerotrust.risk.domain.*;
import com.zerotrust.risk.entity.*;
import com.zerotrust.risk.exception.DeviceTrustRejectedException;
import com.zerotrust.risk.repository.*;
import com.zerotrust.risk.service.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.*;
import org.springframework.context.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.*;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

/** Same business oracle on H2 by default and isolated, guarded MySQL with explicit QA opt-in. */
@SpringBootTest(properties={"spring.jpa.hibernate.ddl-auto=validate","spring.flyway.clean-disabled=true",
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration,org.springframework.boot.autoconfigure.data.redis.RedisReactiveAutoConfiguration,org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration"})
@ActiveProfiles("test")
@ContextConfiguration(initializers=SubjectDeviceLifecycleRegressionTests.StorageGuard.class)
@Import(SubjectDeviceLifecycleRegressionTests.Fixture.class)
class SubjectDeviceLifecycleRegressionTests {
    static final boolean NATIVE=Boolean.getBoolean("qa.mysql.audit");
    static final String RUN=UUID.randomUUID().toString(),REQUESTER="qa-fix04-admin";
    static final Instant NOW=MySqlQaBootstrap.NOW;
    @Autowired DeviceTrustLifecycle lifecycle;
    @Autowired TrustedDeviceRegistrationService registration;
    @Autowired DeviceRecognitionService recognition;
    @Autowired KnownDeviceRepository devices;
    @Autowired DeviceFingerprintHasher hasher;
    @Autowired JdbcTemplate jdbc;
    @Autowired PlatformTransactionManager transactions;
    @MockitoBean RedisAuthenticationFailureStore redis;
    @DynamicPropertySource static void settings(DynamicPropertyRegistry p) {
        p.add("spring.datasource.url",()->NATIVE?MySqlQaBootstrap.URL:"jdbc:h2:mem:fix04_"+RUN+";MODE=MySQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE;LOCK_TIMEOUT=10000");
        p.add("spring.datasource.driver-class-name",()->NATIVE?"com.mysql.cj.jdbc.Driver":"org.h2.Driver");
        p.add("spring.datasource.username",()->NATIVE?"risk_qa":"sa");
        p.add("spring.datasource.password",()->NATIVE?MySqlQaBootstrap.password():"");
        p.add("risk.device-fingerprint.pepper",()->"qa-fix04-only-synthetic-device-pepper");
    }
    static class StorageGuard implements ApplicationContextInitializer<ConfigurableApplicationContext> {
        public void initialize(ConfigurableApplicationContext context) {if(NATIVE)new MySqlQaBootstrap().initialize(context);}
    }
    @TestConfiguration static class Fixture {
        @Bean @Primary Clock subjectClock(){return Clock.fixed(NOW,ZoneOffset.UTC);}
    }
    @BeforeEach void identity() {
        jdbc.execute((org.springframework.jdbc.core.ConnectionCallback<Void>)c->{
            if(NATIVE)MySqlQaBootstrap.identity(c);
            else assertThat(c.getMetaData().getURL()).startsWith("jdbc:h2:mem:fix04_");return null;
        });
    }
    String own(String subject) {
        if(NATIVE)jdbc.update("INSERT INTO qa01c1_fixture_manifest(subject_id,run_id,owner) VALUES(?,?,'01C1')",subject,RUN);
        return subject;
    }
    String subject(){return own(UUID.randomUUID().toString());}
    String padded(String subject){return " \t"+subject+"\r\n ";}
    DeviceRecognitionStatus recognize(String subject,String device) {
        return recognition.recognize(new LoginContext(subject,"session","client","192.0.2.1",null,device,NOW)).status();
    }
    KnownDeviceEntity device(String subject,String id){return devices.findBySubjectIdAndDeviceFingerprintHash(subject,hasher.hash(subject,id)).orElseThrow();}
    void transaction(Runnable work){new TransactionTemplate(transactions).executeWithoutResult(s->work.run());}

    @Test void sameSubmittedSubjectMustReferToRegisteredDeviceDuringRecognition() {
        String s=subject();registration.trustAfterMfa(padded(s),"device",0);
        assertThat(recognize(padded(s),"device")).isEqualTo(DeviceRecognitionStatus.TRUSTED);
        assertThat(recognize(s,"device")).isEqualTo(DeviceRecognitionStatus.TRUSTED);
        assertThat(devices.findAllBySubjectId(s)).hasSize(1);
    }
    @Test void resetOfSameSubmittedSubjectMustRevokeDeviceAndFenceCanonicalGeneration() {
        String s=subject();registration.trustAfterMfa(padded(s),"device",0);UUID op=UUID.randomUUID();
        lifecycle.revoke(padded(s),op,REQUESTER);
        assertThat(device(s,"device").getStatus()).isEqualTo(DeviceStatus.REVOKED);
        assertThat(lifecycle.snapshot(s)).isEqualTo(new DeviceTrustLifecycle.Snapshot(1,true));
        assertThat(lifecycle.snapshot(padded(s))).isEqualTo(new DeviceTrustLifecycle.Snapshot(1,true));
        assertThat(jdbc.queryForObject("SELECT subject_id FROM device_trust_revocations WHERE operation_id=?",String.class,op.toString())).isEqualTo(s);
        assertThat(jdbc.queryForObject("SELECT revoked_count FROM device_trust_revocations WHERE operation_id=?",Integer.class,op.toString())).isEqualTo(1);
        lifecycle.complete(padded(s),op,REQUESTER);
        assertThat(recognize(s,"device")).isEqualTo(DeviceRecognitionStatus.REAUTHENTICATION_REQUIRED);
    }
    @Test void resetPendingStaleGenerationAndCompletionStayFenced() {
        String s=subject();registration.trustAfterMfa(s,"old",0);UUID op=UUID.randomUUID();lifecycle.revoke(padded(s),op,REQUESTER);
        assertThatThrownBy(()->registration.trustAfterMfa(s,"pending",1)).isInstanceOf(DeviceTrustRejectedException.class);
        lifecycle.complete(s,op,REQUESTER);
        assertThat(lifecycle.snapshot(padded(s))).isEqualTo(new DeviceTrustLifecycle.Snapshot(1,false));
        assertThatThrownBy(()->registration.trustAfterMfa(padded(s),"stale",0)).isInstanceOf(DeviceTrustRejectedException.class);
        assertThatThrownBy(()->registration.trustAfterMfa(s,"old",1)).isInstanceOf(DeviceTrustRejectedException.class);
        registration.trustAfterMfa(padded(s),"fresh",1);
        assertThat(recognize(s,"fresh")).isEqualTo(DeviceRecognitionStatus.TRUSTED);
        assertThat(recognize(padded(s),"old")).isEqualTo(DeviceRecognitionStatus.REAUTHENTICATION_REQUIRED);
    }
    @Test void securityRevokedDeviceCannotBeTrustedByAnAliasOrReset() {
        String s=subject();registration.trustAfterMfa(s,"device",0);transaction(()->device(s,"device").revoke(NOW));
        assertThatThrownBy(()->registration.trustAfterMfa(padded(s),"device",0)).isInstanceOf(DeviceTrustRejectedException.class);
        UUID op=UUID.randomUUID();lifecycle.revoke(padded(s),op,REQUESTER);lifecycle.complete(padded(s),op,REQUESTER);
        assertThat(device(s,"device").getRevocationReason()).isEqualTo("SECURITY");
        assertThat(recognize(padded(s),"device")).isEqualTo(DeviceRecognitionStatus.REVOKED);
        assertThatThrownBy(()->registration.trustAfterMfa(s,"device",1)).isInstanceOf(DeviceTrustRejectedException.class);
    }
    @Test void duplicateRegistrationAndRepeatedResetRemainIdempotentAcrossAliases() {
        String s=subject();registration.trustAfterMfa(s,"device",0);registration.trustAfterMfa(padded(s),"device",0);
        assertThat(devices.findAllBySubjectId(s)).hasSize(1);
        UUID op=UUID.randomUUID();lifecycle.revoke(s,op,REQUESTER);lifecycle.revoke(padded(s),op,REQUESTER);
        lifecycle.complete(padded(s),op,REQUESTER);lifecycle.complete(s,op,REQUESTER);
        assertThat(lifecycle.generation(padded(s))).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM device_trust_revocations WHERE operation_id=?",Integer.class,op.toString())).isEqualTo(1);
    }
    @Test void sameDeviceIdentifierCannotTransferTrustOrResetOwnershipBetweenUsers() {
        String a=subject(),b=subject();registration.trustAfterMfa(padded(a),"shared-device",0);
        assertThat(recognize(padded(b),"shared-device")).isEqualTo(DeviceRecognitionStatus.NEW);
        assertThat(hasher.hash(padded(a),"shared-device")).isNotEqualTo(hasher.hash(b,"shared-device"));
        registration.trustAfterMfa(b,"shared-device",0);UUID op=UUID.randomUUID();lifecycle.revoke(padded(a),op,REQUESTER);
        assertThatThrownBy(()->lifecycle.revoke(b,op,REQUESTER)).isInstanceOf(DeviceTrustRejectedException.class);
        assertThatThrownBy(()->lifecycle.complete(b,op,REQUESTER)).isInstanceOf(DeviceTrustRejectedException.class);
        assertThatThrownBy(()->lifecycle.complete(a,op,"other-requester")).isInstanceOf(DeviceTrustRejectedException.class);
        assertThat(recognize(b,"shared-device")).isEqualTo(DeviceRecognitionStatus.TRUSTED);
        assertThat(lifecycle.generation(b)).isZero();
        lifecycle.complete(padded(a),op,REQUESTER);
    }
    @ParameterizedTest @ValueSource(strings={"uppercase-uuid","opaque-invalid-uuid","federated-id"})
    void stringContractRetainsOpaqueAndUppercaseIdentity(String kind) {
        String id=UUID.randomUUID().toString();String s=own(switch(kind){case "uppercase-uuid"->id.toUpperCase(Locale.ROOT);case "federated-id"->"f:qa-component:"+id;default->"not-a-uuid-"+id;});
        registration.trustAfterMfa(padded(s),"device",0);
        assertThat(device(s,"device").getSubjectId()).isEqualTo(s);
        assertThat(recognize(padded(s),"device")).isEqualTo(DeviceRecognitionStatus.TRUSTED);
        assertThat(lifecycle.generation(s)).isZero();
    }
    @Test void invalidIdentityIsRejectedBeforeAnyLifecycleRowsAreWritten() {
        long before=jdbc.queryForObject("SELECT COUNT(*) FROM subject_device_trust",Long.class);
        for(String s:Arrays.asList(null,""," \t\r\n","x".repeat(256))){
            assertThatThrownBy(()->lifecycle.generation(s)).isInstanceOf(RuntimeException.class);
            assertThatThrownBy(()->lifecycle.snapshot(s)).isInstanceOf(RuntimeException.class);
            assertThatThrownBy(()->lifecycle.revoke(s,UUID.randomUUID(),REQUESTER)).isInstanceOf(RuntimeException.class);
            assertThatThrownBy(()->lifecycle.complete(s,UUID.randomUUID(),REQUESTER)).isInstanceOf(RuntimeException.class);
            assertThatThrownBy(()->registration.trustAfterMfa(s,"device",0)).isInstanceOf(RuntimeException.class);
        }
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM subject_device_trust",Long.class)).isEqualTo(before);
    }
    @Test void deviceAbsenceAndNewDeviceKeepTheirStatuses() {
        String s=subject();assertThat(recognize(padded(s),null)).isEqualTo(DeviceRecognitionStatus.MISSING);
        assertThat(recognize(padded(s),"new")).isEqualTo(DeviceRecognitionStatus.NEW);
    }
    @Test void canonicalDeviceCreatedBeforeNormalizationRemainsReadable() {
        String s=subject();KnownDeviceEntity existing=new KnownDeviceEntity(s,hasher.hash(s,"legacy-device"),NOW);
        existing.trust(NOW);devices.saveAndFlush(existing);
        assertThat(recognize(padded(s),"legacy-device")).isEqualTo(DeviceRecognitionStatus.TRUSTED);
        assertThat(device(s,"legacy-device").getDeviceFingerprintHash()).isEqualTo(existing.getDeviceFingerprintHash());
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void canonicalAndPaddedTransactionsContendOnTheSameGuard(boolean revokeFirst) throws Exception {
        String s=subject();lifecycle.generation(s);UUID op=UUID.randomUUID();
        CountDownLatch holding=new CountDownLatch(1),entering=new CountDownLatch(1),release=new CountDownLatch(1);
        AtomicLong holderId=new AtomicLong(),waiterId=new AtomicLong();ExecutorService pool=Executors.newFixedThreadPool(2);
        try {
            Future<?> holder=pool.submit(()->transaction(()->{
                holderId.set(connectionId());if(revokeFirst)lifecycle.revoke(padded(s),op,REQUESTER);else registration.trustAfterMfa(padded(s),"device",0);
                holding.countDown();waitFor(release);
            }));waitFor(holding);
            Future<?> waiter=pool.submit(()->transaction(()->{
                waiterId.set(connectionId());entering.countDown();if(revokeFirst)registration.trustAfterMfa(s,"device",0);else lifecycle.revoke(s,op,REQUESTER);
            }));waitFor(entering);
            assertThat(holderId.get()).isNotEqualTo(waiterId.get());
            await().atMost(Duration.ofSeconds(7)).untilAsserted(()->{
                if(NATIVE){var row=jdbc.queryForList("SHOW FULL PROCESSLIST").stream().filter(r->((Number)r.get("Id")).longValue()==waiterId.get()).findFirst().orElseThrow();assertThat(row.get("Command")).isEqualTo("Query");assertThat(Objects.toString(row.get("Info"))).containsIgnoringCase("subject_device_trust");}
                else {var row=jdbc.queryForMap("SELECT SESSION_STATE,BLOCKER_ID FROM INFORMATION_SCHEMA.SESSIONS WHERE SESSION_ID=?",waiterId.get());assertThat(row.get("session_state")).isEqualTo("BLOCKED");assertThat(row.get("blocker_id")).isInstanceOf(Number.class);assertThat(((Number)row.get("blocker_id")).longValue()).isEqualTo(holderId.get());}
            });assertThat(waiter.isDone()).isFalse();release.countDown();holder.get(25,TimeUnit.SECONDS);
            if(revokeFirst)assertThatThrownBy(()->waiter.get(25,TimeUnit.SECONDS)).isInstanceOf(ExecutionException.class).hasCauseInstanceOf(DeviceTrustRejectedException.class);
            else {waiter.get(25,TimeUnit.SECONDS);assertThat(device(s,"device").getStatus()).isEqualTo(DeviceStatus.REVOKED);}
            assertThat(lifecycle.snapshot(padded(s))).isEqualTo(new DeviceTrustLifecycle.Snapshot(1,true));
            System.out.printf("FIX04 GUARD storage=%s revokeFirst=%s holder=%d waiter=%d sharedSubjectLock=true%n",NATIVE?"MySQL":"H2",revokeFirst,holderId.get(),waiterId.get());
        }finally{release.countDown();pool.shutdownNow();assertThat(pool.awaitTermination(25,TimeUnit.SECONDS)).isTrue();}
    }
    long connectionId(){return jdbc.queryForObject(NATIVE?"SELECT CONNECTION_ID()":"SELECT SESSION_ID()",Long.class);}
    static void waitFor(CountDownLatch latch){try{if(!latch.await(20,TimeUnit.SECONDS))throw new AssertionError("checkpoint timeout");}catch(InterruptedException e){Thread.currentThread().interrupt();throw new AssertionError(e);}}
}
