package com.zerotrust.risk.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.entity.DeviceStatus;
import com.zerotrust.risk.entity.KnownDeviceEntity;
import com.zerotrust.risk.exception.DeviceTrustRejectedException;
import com.zerotrust.risk.repository.KnownDeviceRepository;
import com.zerotrust.risk.repository.RedisAuthenticationFailureStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

/** Business-success oracles; historical POSTFIX-02 characterization sources remain untouched. */
abstract class TimestampLifecyclePrecisionContract {
    static final AtomicReference<Instant> NOW = new AtomicReference<>(at(123456789));
    static final String RUN = System.getProperty("postfix03b.runUUID", UUID.randomUUID().toString());
    @Autowired TrustedDeviceRegistrationService registration;
    @Autowired DeviceTrustLifecycle lifecycle;
    @Autowired DeviceRecognitionService recognition;
    @Autowired KnownDeviceRepository devices;
    @Autowired DeviceFingerprintHasher hasher;
    @Autowired JdbcTemplate jdbc;
    @Autowired PlatformTransactionManager transactions;
    @MockitoBean RedisAuthenticationFailureStore redis;

    @TestConfiguration static class TimeConfig {
        @Bean @Primary Clock precisionClock() {
            return new Clock() {
                public ZoneId getZone() { return ZoneOffset.UTC; }
                public Clock withZone(ZoneId zone) { if (!ZoneOffset.UTC.equals(zone)) throw new IllegalArgumentException("UTC required"); return this; }
                public Instant instant() { return NOW.get(); }
            };
        }
    }
    static Instant at(int nanos) { return Instant.parse("2026-10-15T00:00:00Z").plusNanos(nanos); }
    // Exact historical input -> persisted microsecond expectations; independent of production quantizer.
    static Stream<org.junit.jupiter.params.provider.Arguments> historical() {
        int[] input={0,123456000,123456001,123456499,123456500,123456501,123456789,123456999,999999499,999999500,999999999};
        long[] output={0,123456000,123456000,123456000,123457000,123457000,123457000,123457000,999999000,1000000000,1000000000};
        return java.util.stream.IntStream.range(0,input.length).mapToObj(i -> org.junit.jupiter.params.provider.Arguments.of(input[i],Instant.parse("2026-10-15T00:00:00Z").plusNanos(output[i])));
    }
    String subject() { return "pf03b-"+RUN+"-"+UUID.randomUUID(); }
    String device() { return "device-"+UUID.randomUUID(); }
    KnownDeviceEntity stored(String s) { return devices.findAllBySubjectId(s).stream().filter(d -> s.equals(d.getSubjectId())).findFirst().orElseThrow(); }
    Instant first(String s) { return jdbc.queryForObject("SELECT first_seen_at FROM known_devices WHERE subject_id=?",Timestamp.class,s).toInstant(); }
    String recognition(String s,String d) { return recognition.recognize(new LoginContext(s,"session","Client","192.0.2.3",null,d,NOW.get())).status().name(); }
    List<Map<String,Object>> state(String s) {
        return jdbc.queryForList("SELECT generation,pending_operation_id FROM subject_device_trust WHERE subject_id=?",s);
    }
    List<Map<String,String>> audit(String s) {
        return jdbc.queryForList("SELECT * FROM device_trust_revocations WHERE subject_id=? ORDER BY operation_id",s).stream().map(row -> {
            Map<String,String> copy=new TreeMap<>(); row.forEach((k,v)->copy.put(k.toLowerCase(Locale.ROOT),v==null?null:v.toString()));return copy;
        }).toList();
    }
    void record(String name,String s,Instant input) throws Exception {
        var d=stored(s);Map<String,Object> event=new LinkedHashMap<>();
        event.put("case",name);event.put("subject",s);event.put("clock",input.toString());event.put("persisted_first",d.getFirstSeenAt().toString());
        event.put("status",d.getStatus().name());event.put("trusted_at",Objects.toString(d.getTrustedAt(),null));event.put("revoked_at",Objects.toString(d.getRevokedAt(),null));
        event.put("state",state(s));event.put("audit",audit(s));
        System.out.println("POSTFIX03B_EVIDENCE "+new ObjectMapper().writeValueAsString(event));
    }
    void revoked(String s,String d,UUID op,Instant expected) {
        var row=stored(s);assertThat(row.getStatus()).isEqualTo(DeviceStatus.REVOKED);
        assertThat(row.getRevocationReason()).isEqualTo("MFA_RESET");assertThat(row.getRevokedAt()).isEqualTo(expected);
        assertThat(lifecycle.snapshot(s)).isEqualTo(new DeviceTrustLifecycle.Snapshot(1,true));
        assertThat(jdbc.queryForObject("SELECT pending_operation_id FROM subject_device_trust WHERE subject_id=?",String.class,s)).isEqualTo(op.toString());
        assertThat(audit(s)).hasSize(1);assertThat(audit(s).get(0).get("revoked_count")).isEqualTo("1");
        assertThat(jdbc.queryForObject("SELECT revoked_at FROM device_trust_revocations WHERE subject_id=?",Timestamp.class,s).toInstant()).isEqualTo(expected);
        assertThat(recognition(s,d)).isEqualTo("REAUTHENTICATION_REQUIRED");
    }
    void completeAndReplay(String s,UUID op) {
        var before=audit(s);lifecycle.revoke(s,op,"Admin");assertThat(audit(s)).isEqualTo(before);
        lifecycle.complete(s,op,"Admin");assertThat(lifecycle.snapshot(s)).isEqualTo(new DeviceTrustLifecycle.Snapshot(1,false));
        assertThat(audit(s).get(0).get("completed_at")).isNotNull();
        var completed=audit(s);lifecycle.complete(s,op,"Admin");lifecycle.revoke(s,op,"Admin");assertThat(audit(s)).isEqualTo(completed);
    }
    @ParameterizedTest @MethodSource("historical")
    void historicalRegistrationImmediateRevokeSucceedsWithoutClockAdvance(int nanos,Instant expected) throws Exception {
        String s=subject(),d=device();UUID op=UUID.randomUUID();NOW.set(at(nanos));
        registration.trustAfterMfa(s,d,0);assertThat(first(s)).isEqualTo(expected);record("registered",s,NOW.get());
        lifecycle.revoke(s,op,"Admin");revoked(s,d,op,expected);completeAndReplay(s,op);
        assertThat(NOW.get()).isEqualTo(at(nanos));record("immediate_revoke_completed",s,NOW.get());
    }
    @ParameterizedTest @MethodSource("historical")
    void existingRoundedMicrosecondRowsRemainRevocable(int nanos,Instant expected) throws Exception {
        String s=subject(),d=device();UUID op=UUID.randomUUID();NOW.set(at(nanos));
        jdbc.update("INSERT INTO subject_device_trust(subject_id,generation) VALUES(?,0)",s);
        jdbc.update("INSERT INTO known_devices(subject_id,device_fingerprint_hash,status,first_seen_at,last_seen_at,trusted_at,version) VALUES(?,?,'TRUSTED',?,?,?,0)",
                s,hasher.hash(s,d),Timestamp.from(expected),Timestamp.from(expected),Timestamp.from(expected));
        assertThat(first(s)).isEqualTo(expected);lifecycle.revoke(s,op,"Admin");revoked(s,d,op,expected);completeAndReplay(s,op);
        record("existing_microsecond_row",s,NOW.get());
    }
    @Test void repeatedTrustAndFrozenClockAreConsistentAfterReload() {
        String s=subject(),d=device();NOW.set(at(123456789));registration.trustAfterMfa(s,d,0);registration.trustAfterMfa(s,d,0);
        var row=stored(s);assertThat(row.getFirstSeenAt()).isEqualTo(at(123457000));assertThat(row.getTrustedAt()).isEqualTo(at(123457000));
        assertThat(row.getLastSeenAt()).isEqualTo(at(123457000));assertThat(recognition(s,d)).isEqualTo("TRUSTED");
    }
    @Test void sameOuterTransactionFlushRefreshRegistrationAndRevokeSucceeds() {
        String s=subject(),d=device();UUID op=UUID.randomUUID();NOW.set(at(123456789));
        new TransactionTemplate(transactions).executeWithoutResult(tx->{registration.trustAfterMfa(s,d,0);lifecycle.revoke(s,op,"Admin");});
        revoked(s,d,op,at(123457000));completeAndReplay(s,op);
    }
    @Test void backwardClockRejectsAndRollsBackThenSameOperationRetriesAtValidClock() {
        String s=subject(),d=device();UUID op=UUID.randomUUID();NOW.set(at(123456789));registration.trustAfterMfa(s,d,0);
        var before=state(s);NOW.set(at(123454789));
        assertThatThrownBy(()->lifecycle.revoke(s,op,"Admin")).isInstanceOf(IllegalArgumentException.class).hasMessage("revokedAt must not be before firstSeenAt");
        assertThat(state(s)).isEqualTo(before);assertThat(audit(s)).isEmpty();assertThat(stored(s).getStatus()).isEqualTo(DeviceStatus.TRUSTED);
        assertThat(stored(s).getVersion()).isZero();assertThat(stored(s).getRevokedAt()).isNull();
        assertThat(recognition(s,d)).isEqualTo("TRUSTED");NOW.set(at(123456789));lifecycle.revoke(s,op,"Admin");revoked(s,d,op,at(123457000));completeAndReplay(s,op);
    }
    @Test void invalidChronologyInsideOuterTransactionRollsBackNewRegistrationAndState() {
        String s=subject(),d=device();NOW.set(at(123456789));
        assertThatThrownBy(()->new TransactionTemplate(transactions).executeWithoutResult(tx->{
            registration.trustAfterMfa(s,d,0);NOW.set(at(123454789));lifecycle.revoke(s,UUID.randomUUID(),"Admin");
        })).isInstanceOf(IllegalArgumentException.class).hasMessage("revokedAt must not be before firstSeenAt");
        assertThat(devices.findAllBySubjectId(s)).isEmpty();assertThat(state(s)).isEmpty();assertThat(audit(s)).isEmpty();
    }
    @Test void backwardClockAcrossMicrosecondBoundaryRejectsEvenWhenOnlyTwoNanoseconds() {
        String s=subject(),d=device();NOW.set(at(123456501));registration.trustAfterMfa(s,d,0);NOW.set(at(123456499));
        assertThatThrownBy(()->lifecycle.revoke(s,UUID.randomUUID(),"Admin")).isInstanceOf(IllegalArgumentException.class);
        assertThat(lifecycle.snapshot(s)).isEqualTo(new DeviceTrustLifecycle.Snapshot(0,false));assertThat(audit(s)).isEmpty();
    }
    @Test void subprecisionInstantsInSameStoredMicrosecondAreEquivalentWithoutClamping() {
        String s=subject(),d=device();UUID op=UUID.randomUUID();NOW.set(at(123456789));registration.trustAfterMfa(s,d,0);
        NOW.set(at(123456700));lifecycle.revoke(s,op,"Admin");revoked(s,d,op,at(123457000));
    }
    @Test void futurePersistedRowIsNotSilentlyClampedOrRepaired() {
        String s=subject(),d=device();NOW.set(at(123456789));Instant future=at(123457000).plusSeconds(1);
        jdbc.update("INSERT INTO subject_device_trust(subject_id,generation) VALUES(?,0)",s);
        jdbc.update("INSERT INTO known_devices(subject_id,device_fingerprint_hash,status,first_seen_at,last_seen_at,trusted_at,version) VALUES(?,?,'TRUSTED',?,?,?,0)",
                s,hasher.hash(s,d),Timestamp.from(future),Timestamp.from(future),Timestamp.from(future));
        assertThatThrownBy(()->lifecycle.revoke(s,UUID.randomUUID(),"Admin")).isInstanceOf(IllegalArgumentException.class);
        assertThat(first(s)).isEqualTo(future);assertThat(lifecycle.snapshot(s)).isEqualTo(new DeviceTrustLifecycle.Snapshot(0,false));assertThat(audit(s)).isEmpty();
    }
    @Test void securityRevocationAtImmediateClockPersistsAndRetainsPrecedence() {
        String s=subject(),d=device();NOW.set(at(123456789));registration.trustAfterMfa(s,d,0);
        new TransactionTemplate(transactions).executeWithoutResult(tx->{var row=stored(s);row.revoke(NOW.get());devices.flush();});
        assertThat(stored(s).getRevokedAt()).isEqualTo(at(123457000));assertThat(recognition(s,d)).isEqualTo("REVOKED");
        UUID op=UUID.randomUUID();lifecycle.revoke(s,op,"Admin");lifecycle.complete(s,op,"Admin");
        assertThat(stored(s).getRevocationReason()).isEqualTo("SECURITY");assertThat(audit(s).get(0).get("revoked_count")).isEqualTo("0");
        assertThatThrownBy(()->registration.trustAfterMfa(s,d,1)).isInstanceOf(DeviceTrustRejectedException.class);
    }
    @Test void completionAndReplayRetainExactOwnersAndGenerationFences() {
        String a=subject(),b=a.replace("pf03b","PF03B"),d=device();UUID op=UUID.randomUUID();NOW.set(at(123456789));
        registration.trustAfterMfa(a,d,0);registration.trustAfterMfa(b,d,0);lifecycle.revoke(a,op,"Admin");
        assertThat(lifecycle.snapshot(b)).isEqualTo(new DeviceTrustLifecycle.Snapshot(0,false));assertThat(recognition(b,d)).isEqualTo("TRUSTED");
        assertThatThrownBy(()->lifecycle.complete(b,op,"Admin")).isInstanceOf(DeviceTrustRejectedException.class);
        assertThatThrownBy(()->lifecycle.complete(a,op,"admin")).isInstanceOf(DeviceTrustRejectedException.class);
        assertThatThrownBy(()->registration.trustAfterMfa(a,device(),1)).isInstanceOf(DeviceTrustRejectedException.class);
        completeAndReplay(a,op);var baseline=audit(a);
        assertThatThrownBy(()->lifecycle.complete(b,op,"Admin")).isInstanceOf(DeviceTrustRejectedException.class);
        assertThat(audit(a)).isEqualTo(baseline);assertThat(audit(b)).isEmpty();
        assertThatThrownBy(()->registration.trustAfterMfa(a,device(),0)).isInstanceOf(DeviceTrustRejectedException.class);
        registration.trustAfterMfa(a,device(),1);assertThat(devices.findAllBySubjectId(a)).hasSize(2);
    }
    @Test void concurrentRegistrationCommitIsSeenByWaitingRevokeAtFrozenClock() throws Exception {
        String s=subject(),d=device();UUID op=UUID.randomUUID();NOW.set(at(123456789));
        var registered=new CountDownLatch(1);var release=new CountDownLatch(1);var started=new CountDownLatch(1);
        var waiter=new AtomicLong();var pool=Executors.newFixedThreadPool(2);
        String product=jdbc.execute((org.springframework.jdbc.core.ConnectionCallback<String>)c->c.getMetaData().getDatabaseProductName());
        try {
            var t1=pool.submit(()->new TransactionTemplate(transactions).executeWithoutResult(tx->{
                registration.trustAfterMfa(s,d,0);registered.countDown();
                try { if(!release.await(20,TimeUnit.SECONDS))throw new IllegalStateException("registration latch timeout"); }
                catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException(e);}
            }));
            assertThat(registered.await(10,TimeUnit.SECONDS)).isTrue();
            var t2=pool.submit(()->new TransactionTemplate(transactions).executeWithoutResult(tx->{
                if("MySQL".equals(product))waiter.set(jdbc.queryForObject("SELECT CONNECTION_ID()",Long.class));
                started.countDown();lifecycle.revoke(s,op,"Admin");
            }));
            assertThat(started.await(5,TimeUnit.SECONDS)).isTrue();
            await().atMost(Duration.ofSeconds(8)).untilAsserted(()->{
                if("MySQL".equals(product))assertThat(jdbc.queryForList("SHOW FULL PROCESSLIST").stream().anyMatch(x->((Number)x.get("Id")).longValue()==waiter.get()&&Objects.toString(x.get("Info"),"").contains("subject_device_trust"))).isTrue();
                else assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM information_schema.sessions WHERE session_state='BLOCKED' OR executing_statement LIKE 'INSERT IGNORE INTO subject_device_trust%'",Long.class)).isPositive();
            });
            assertThat(t2.isDone()).isFalse();release.countDown();t1.get(15,TimeUnit.SECONDS);t2.get(15,TimeUnit.SECONDS);
            revoked(s,d,op,at(123457000));completeAndReplay(s,op);record("concurrent_registration_revoke",s,NOW.get());
        } finally {release.countDown();pool.shutdownNow();}
    }
}
