package com.zerotrust.risk.migration;

import com.zerotrust.risk.diagnostic.SubjectIdentityMySqlSupport;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.entity.KnownDeviceEntity;
import com.zerotrust.risk.exception.DeviceTrustRejectedException;
import com.zerotrust.risk.repository.*;
import com.zerotrust.risk.service.*;
import db.migration.V5__isolate_subject_identity;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.migration.Context;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Prepared under Gate A; every native method remains disabled until independent Gate B + exact manifest. */
@EnabledIfSystemProperty(named="postfix03a.gateB",matches="APPROVED")
class SubjectIdentityMigrationMySqlTests {
    static String scenario(){return System.getProperty("postfix03a.scenario");}
    static String subject(String suffix){return "pf03a-"+SubjectIdentityMySqlSupport.manifest().get("run_uuid")+"-"+scenario()+"-"+suffix;}
    static Flyway flyway(String scenario,String target){return Flyway.configure().dataSource(SubjectIdentityMySqlSupport.dataSource(scenario)).locations("classpath:db/migration").target(target).cleanDisabled(true).load();}

    @Test
    @EnabledIfSystemProperty(named="postfix03a.scenario",matches="fresh|upgrade|collision_case|collision_accent|collision_unicode|collision_opaque|collision_uuid|unsafe_pending|raw_legacy|incompatible|partial_seed|partial|restore")
    void approvedIsolatedMigrationScenario() throws Exception {
        String scenario=scenario();
        try(var c=SubjectIdentityMySqlSupport.connect(scenario)) {
            if(scenario.equals("restore")) {
                var m=SubjectIdentityMySqlSupport.manifest();
                assertThat(SubjectIdentityMigrationPreflight.snapshot(c).sha256()).isEqualTo(m.get("restore_expected_application_sha256"));
                assertThat(SubjectIdentityMySqlSupport.schemaFingerprint(c)).isEqualTo(m.get("restore_expected_schema_sha256"));
                flyway(scenario,"4").validate();SubjectIdentityMySqlSupport.assertBudget(c,scenario);return;
            }
            if(!scenario.equals("partial")) {
                try(var s=c.createStatement();var r=s.executeQuery("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()")) {
                    r.next();assertThat(r.getLong(1)).as("preprovisioned but fresh empty approved schema").isZero();
                }
            }
            if(scenario.equals("fresh")) {
                assertThat(flyway(scenario,"latest").migrate().migrationsExecuted).isEqualTo(5);
                flyway(scenario,"latest").validate();SubjectIdentityMySqlSupport.assertBudget(c,scenario);return;
            }
            if(!scenario.equals("partial"))flyway(scenario,"4").migrate();
            else flyway(scenario,"4").validate();
            if(scenario.equals("partial_seed")) {
                insert(c,"INSERT INTO subject_device_trust(subject_id,generation) VALUES(?,0)",subject("Alice"));
                var before=SubjectIdentityMigrationPreflight.snapshot(c);
                String json=new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(Map.of("expected_application_sha256",before.sha256(),"expected_v4_schema_sha256",SubjectIdentityMySqlSupport.schemaFingerprint(c)));
                Files.writeString(Path.of(System.getProperty("postfix03a.recoveryOutput")),json);
                SubjectIdentityMySqlSupport.assertBudget(c,scenario);return;
            }
            if(scenario.equals("upgrade")) {
                String operation=UUID.randomUUID().toString();
                insert(c,"INSERT INTO subject_device_trust(subject_id,generation,pending_operation_id) VALUES(?,1,?)",subject("Alice"),operation);
                insert(c,"INSERT INTO device_trust_revocations(operation_id,subject_id,requested_by,generation,revoked_count,revoked_at) VALUES(?,?,?,1,1,'2026-10-16 00:00:00.123456')",operation,subject("Alice"),"Admin");
                insert(c,"INSERT INTO subject_device_trust(subject_id,generation) VALUES(?,0)",subject("trusted-legacy"));
                insert(c,"INSERT INTO known_devices(subject_id,device_fingerprint_hash,status,first_seen_at,last_seen_at,trusted_at,version) VALUES(?,?,'TRUSTED','2026-10-15 00:00:00.123456','2026-10-15 00:00:00.123456','2026-10-15 00:00:00.123456',0)",subject("trusted-legacy"),"c".repeat(64));
                insert(c,"INSERT INTO known_devices(subject_id,device_fingerprint_hash,status,first_seen_at,last_seen_at,trusted_at,revoked_at,revocation_reason,version) VALUES(?,?,'REVOKED','2026-10-15 00:00:00.123456','2026-10-16 00:00:00.123456','2026-10-15 00:00:00.123456','2026-10-16 00:00:00.123456','MFA_RESET',1)",subject("Alice"),"d".repeat(64));
                insert(c,"INSERT INTO authentication_success_events(event_id,subject_id,client_id,authenticated_at,recorded_at) VALUES(?,?,?,'2026-10-16 00:00:00.123456','2026-10-16 00:00:00.123456')",UUID.randomUUID().toString(),subject("history-only"),"Client");
                var before=SubjectIdentityMigrationPreflight.snapshot(c);
                var fixturesBefore=upgradeFixtureRows(before.tables(),subject("Alice"),subject("trusted-legacy"),operation);
                flyway(scenario,"latest").migrate();flyway(scenario,"latest").validate();
                var after=SubjectIdentityMigrationPreflight.snapshot(c);
                assertThat(after.sha256()).isEqualTo(before.sha256());
                assertThat(upgradeFixtureRows(after.tables(),subject("Alice"),subject("trusted-legacy"),operation)).isEqualTo(fixturesBefore);
            } else if(scenario.equals("partial")) {
                var before=SubjectIdentityMigrationPreflight.snapshot(c);String oldSchema=SubjectIdentityMySqlSupport.schemaFingerprint(c);
                var approved=SubjectIdentityMySqlSupport.manifest();
                assertThat(before.sha256()).isEqualTo(approved.get("partial_expected_application_sha256"));
                assertThat(oldSchema).isEqualTo(approved.get("partial_expected_v4_schema_sha256"));
                byte[] backup=Files.readAllBytes(Path.of(System.getProperty("postfix03a.backupFile")));
                assertThat(SubjectIdentityMySqlSupport.digest(backup)).isEqualTo(approved.get("backup_sha256"));
                AtomicInteger alters=new AtomicInteger();
                Connection injecting=(Connection)Proxy.newProxyInstance(Connection.class.getClassLoader(),new Class<?>[]{Connection.class},(proxy,method,args)->{
                    try {
                        Object result=method.invoke(c,args);
                        if(method.getName().equals("createStatement")) {
                            Statement actual=(Statement)result;
                            return Proxy.newProxyInstance(Statement.class.getClassLoader(),new Class<?>[]{Statement.class},(p,m,a)->{
                                if(m.getName().equals("execute")&&a[0] instanceof String sql&&sql.startsWith("ALTER TABLE")&&alters.incrementAndGet()==2) throw new SQLException("Synthetic second-DDL failure");
                                try{return m.invoke(actual,a);}catch(InvocationTargetException ex){throw ex.getCause();}
                            });
                        }
                        return result;
                    }catch(InvocationTargetException ex){throw ex.getCause();}
                });
                Context context=mock(Context.class);when(context.getConnection()).thenReturn(injecting);
                assertThatThrownBy(()->new V5__isolate_subject_identity().migrate(context)).hasMessageContaining("V5_STOP_PARTIAL_MIGRATION after 1");
                assertThat(SubjectIdentityMigrationPreflight.snapshot(c).sha256()).isEqualTo(before.sha256());
                assertThat(SubjectIdentityMySqlSupport.schemaFingerprint(c)).isNotEqualTo(oldSchema);
                assertThatThrownBy(()->SubjectIdentityMigrationPreflight.inspect(c,true)).hasMessageContaining("PARTIAL_SCHEMA");
                // Recovery is a separately approved external restore into the restore schema, never automatic repair.
                String json=new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(Map.of("expected_application_sha256",before.sha256(),"expected_v4_schema_sha256",oldSchema,"completed_ddl",1));
                Files.writeString(Path.of(System.getProperty("postfix03a.recoveryOutput")),json);
            } else {
                if(scenario.startsWith("collision_")) {
                    String a=subject("Case"),b=subject("case");
                    if(scenario.equals("collision_accent")){a=subject("café");b=subject("cafe");}
                    if(scenario.equals("collision_unicode")){a=subject("café");b=subject("cafe\u0301");}
                    if(scenario.equals("collision_opaque")){a="f:"+subject("Alice");b="f:"+subject("alice");}
                    if(scenario.equals("collision_uuid")){a=UUID.randomUUID().toString();b=a.toUpperCase(Locale.ROOT);}
                    insert(c,"INSERT IGNORE INTO subject_device_trust(subject_id,generation) VALUES(?,0),(?,0)",a,b);
                    insert(c,"INSERT INTO known_devices(subject_id,device_fingerprint_hash,status,first_seen_at,last_seen_at,version) VALUES(?,?,'PENDING','2026-10-16 00:00:00.123456','2026-10-16 00:00:00.123456',0)",b,"a".repeat(64));
                } else if(scenario.equals("unsafe_pending")) {
                    insert(c,"INSERT INTO subject_device_trust(subject_id,generation,pending_operation_id) VALUES(?,1,?)",subject("Alice"),UUID.randomUUID().toString());
                } else if(scenario.equals("raw_legacy")) {
                    insert(c,"INSERT INTO subject_device_trust(subject_id,generation) VALUES(?,0)"," "+subject("Alice")+" ");
                } else {
                    try(var s=c.createStatement()){s.execute("ALTER TABLE subject_device_trust ADD COLUMN unreviewed_state INT");}
                }
                var before=SubjectIdentityMigrationPreflight.snapshot(c);String schema=SubjectIdentityMySqlSupport.schemaFingerprint(c);
                String reason=scenario.startsWith("collision_")?"AMBIGUOUS_SQL_IDENTITY_COLLISION":scenario.equals("unsafe_pending")?"UNEXPLAINED_GENERATION":scenario.equals("raw_legacy")?"NON_NORMALIZED":"COLUMN_LAYOUT";
                assertThatThrownBy(()->flyway(scenario,"latest").migrate()).hasStackTraceContaining(reason);
                assertThat(SubjectIdentityMySqlSupport.schemaFingerprint(c)).isEqualTo(schema);
                assertThat(SubjectIdentityMigrationPreflight.snapshot(c).sha256()).isEqualTo(before.sha256());
            }
            SubjectIdentityMySqlSupport.assertBudget(c,scenario);
        }
    }
    // Pure fixture assertions, also exercised offline against the captured native upgrade rows.
    static Map<String,Map<String,String>> upgradeFixtureRows(Map<String,List<Map<String,String>>> tables,
                                                           String alice,String legacy,String operation) {
        var aliceRow=exactSubjectRow(tables,"subject_device_trust",alice);
        assertThat(aliceRow.get("generation")).isEqualTo("1");
        assertThat(aliceRow.get("pending_operation_id")).isEqualTo(operation);
        var legacyRow=exactSubjectRow(tables,"subject_device_trust",legacy);
        assertThat(legacyRow.get("generation")).isEqualTo("0");
        assertThat(legacyRow.get("pending_operation_id")).isNull();
        var audit=exactSubjectRow(tables,"device_trust_revocations",alice);
        assertThat(audit.get("operation_id")).isEqualTo(operation);
        assertThat(audit.get("requested_by")).isEqualTo("Admin");
        assertThat(audit.get("generation")).isEqualTo("1");
        assertThat(audit.get("revoked_count")).isEqualTo("1");
        assertThat(audit.get("completed_at")).isNull();
        return Map.of("Alice",aliceRow,"trusted-legacy",legacyRow,"audit",audit);
    }
    private static Map<String,String> exactSubjectRow(Map<String,List<Map<String,String>>> tables,String table,String subject) {
        var matches=tables.get(table).stream().filter(row->subject.equals(row.get("subject_id"))).toList();
        assertThat(matches).as("exactly one %s row for exact Java subject %s",table,subject).hasSize(1);
        return matches.iterator().next();
    }
    static void insert(Connection c,String sql,Object...args)throws Exception {
        try(var s=c.prepareStatement(sql)){for(int i=0;i<args.length;i++)s.setObject(i+1,args[i]);s.executeUpdate();}
    }

    @Nested
    @EnabledIfSystemProperty(named="postfix03a.scenario",matches="production")
    @SpringBootTest(properties={"spring.datasource.url=${PF03A_MYSQL_URL}","spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver","spring.datasource.username=pf03a_app","spring.datasource.password=${PF03A_MYSQL_PASSWORD}","spring.jpa.hibernate.ddl-auto=validate","spring.flyway.enabled=false","spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration,org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration"})
    @ActiveProfiles("test")
    @ContextConfiguration(initializers=SubjectIdentityMySqlSupport.class)
    @Import(SubjectIdentityMySqlSupport.TimeConfig.class)
    class ProductionCases {
        @Autowired TrustedDeviceRegistrationService registration;
        @Autowired DeviceTrustLifecycle lifecycle;
        @Autowired DeviceRecognitionService recognition;
        @Autowired DeviceFingerprintHasher hasher;
        @Autowired KnownDeviceRepository devices;
        @Autowired AuthenticationSuccessService history;
        @Autowired AuthenticationSuccessEventRepository events;
        @Autowired JdbcTemplate jdbc;
        @Autowired PlatformTransactionManager transactions;
        @MockitoBean RedisAuthenticationFailureStore redis;
        @AfterEach void budget() throws Exception {try(var c=SubjectIdentityMySqlSupport.connect("production")){SubjectIdentityMySqlSupport.assertBudget(c,"production");}}
        String status(String s,String d){return recognition.recognize(new LoginContext(s,"session","Client","192.0.2.3",null,d,SubjectIdentityMySqlSupport.NOW.get())).status().name();}
        long stateCount(String subject){return jdbc.queryForObject("SELECT COUNT(*) FROM subject_device_trust WHERE subject_id=?",Long.class,subject);}
        void fresh(String...subjects){for(String s:subjects){assertThat(stateCount(s)).isZero();assertThat(devices.findAllBySubjectId(s)).isEmpty();}}

        @Test void exactSubjectClientHistoryScopesUseActualProductionRepository() {
            String a=subject("history-Alice"),b=subject("history-alice");fresh(a,b);
            Instant now=SubjectIdentityMySqlSupport.NOW.get(),first=now.minusSeconds(3),second=now.minusSeconds(2),third=now.minusSeconds(1);
            assertThat(history.recordSuccess(UUID.randomUUID().toString(),a,"Client",first)).isTrue();
            assertThat(history.recordSuccess(UUID.randomUUID().toString(),a,"client",second)).isTrue();
            assertThat(history.recordSuccess(UUID.randomUUID().toString(),b,"Client",third)).isTrue();
            assertThat(events.findRecentAuthenticationTimes(a,"Client",now.minusSeconds(60),now,PageRequest.of(0,10))).containsExactly(first);
            assertThat(events.findRecentAuthenticationTimes(a,"client",now.minusSeconds(60),now,PageRequest.of(0,10))).containsExactly(second);
            assertThat(events.findRecentAuthenticationTimes(b,"Client",now.minusSeconds(60),now,PageRequest.of(0,10))).containsExactly(third);
        }
        @Test void primaryAndCompositeUniqueKeysUseExactSubjectComparator() {
            String a=subject("index-Alice"),b=subject("index-alice");fresh(a,b);lifecycle.generation(a);lifecycle.generation(b);
            for(String s:List.of(a,b))jdbc.update("INSERT INTO known_devices(subject_id,device_fingerprint_hash,status,first_seen_at,last_seen_at,version) VALUES(?,?,'PENDING',?,?,0)",s,"b".repeat(64),java.sql.Timestamp.from(SubjectIdentityMySqlSupport.NOW.get()),java.sql.Timestamp.from(SubjectIdentityMySqlSupport.NOW.get()));
            assertThat(devices.findBySubjectIdAndDeviceFingerprintHash(a,"b".repeat(64))).get().extracting(KnownDeviceEntity::getSubjectId).isEqualTo(a);
            assertThat(devices.findBySubjectIdAndDeviceFingerprintHash(b,"b".repeat(64))).get().extracting(KnownDeviceEntity::getSubjectId).isEqualTo(b);
            assertThatThrownBy(()->jdbc.update("INSERT INTO subject_device_trust(subject_id,generation) VALUES(?,0)",a)).isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
            assertThatThrownBy(()->jdbc.update("INSERT INTO known_devices(subject_id,device_fingerprint_hash,status,first_seen_at,last_seen_at,version) VALUES(?,?,'PENDING',?,?,0)",a,"b".repeat(64),java.sql.Timestamp.from(SubjectIdentityMySqlSupport.NOW.get()),java.sql.Timestamp.from(SubjectIdentityMySqlSupport.NOW.get()))).isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
            var explain=jdbc.queryForList("EXPLAIN SELECT * FROM known_devices FORCE INDEX (idx_known_devices_subject_status) WHERE subject_id=? AND status='PENDING'",a);
            assertThat(explain).hasSize(1);assertThat(explain.get(0).get("key")).isEqualTo("idx_known_devices_subject_status");
            // Forced usability is not an assertion about cost-based plans or production latency.
        }
        @Test void rejectedCompletionAndReplayRollBackFreshWrongOwnerState() {
            String a=subject("owner-Alice"),b=subject("owner-alice");fresh(a,b);UUID op=UUID.randomUUID();String device="device-"+UUID.randomUUID();
            registration.trustAfterMfa(a,device,0);lifecycle.revoke(a,op,"Admin");
            assertThat(status(a,device)).isEqualTo("REAUTHENTICATION_REQUIRED");
            assertThatThrownBy(()->registration.trustAfterMfa(a,"pending-device",1)).isInstanceOf(DeviceTrustRejectedException.class);
            assertThatThrownBy(()->lifecycle.complete(b,op,"Admin")).isInstanceOf(DeviceTrustRejectedException.class);assertThat(stateCount(b)).isZero();
            lifecycle.complete(a,op,"Admin");var baseline=jdbc.queryForList("SELECT * FROM device_trust_revocations WHERE operation_id=?",op.toString());
            assertThatThrownBy(()->lifecycle.complete(b,op,"Admin")).isInstanceOf(DeviceTrustRejectedException.class);assertThat(stateCount(b)).isZero();
            assertThatThrownBy(()->lifecycle.complete(a,op,"admin")).isInstanceOf(DeviceTrustRejectedException.class);
            assertThatThrownBy(()->lifecycle.revoke(b,op,"Admin")).isInstanceOf(DeviceTrustRejectedException.class);assertThat(stateCount(b)).isZero();
            lifecycle.complete(a,op,"Admin");assertThat(jdbc.queryForList("SELECT * FROM device_trust_revocations WHERE operation_id=?",op.toString())).isEqualTo(baseline);
            assertThatThrownBy(()->registration.trustAfterMfa(a,"stale-attempt",0)).isInstanceOf(DeviceTrustRejectedException.class);
            assertThatThrownBy(()->registration.trustAfterMfa(a,device,1)).isInstanceOf(DeviceTrustRejectedException.class);
            registration.trustAfterMfa(a,"fresh-device",1);
        }
        @Test void independentPreexistingSubjectLocksAllowOtherSubjectLifecycle() throws Exception {
            String a=subject("lock-Alice"),b=subject("lock-alice");fresh(a,b);lifecycle.generation(a);lifecycle.generation(b);
            var held=new CountDownLatch(1);var release=new CountDownLatch(1);var pool=Executors.newFixedThreadPool(2);
            try {
                Future<?> first=pool.submit(()->new TransactionTemplate(transactions).executeWithoutResult(tx->{lifecycle.requireGeneration(a,0);held.countDown();try{if(!release.await(10,TimeUnit.SECONDS))throw new IllegalStateException("test latch");}catch(InterruptedException ex){Thread.currentThread().interrupt();throw new IllegalStateException(ex);}}));
                assertThat(held.await(5,TimeUnit.SECONDS)).isTrue();
                Future<?> second=pool.submit(()->{registration.trustAfterMfa(b,"device",0);UUID op=UUID.randomUUID();lifecycle.revoke(b,op,"Admin");lifecycle.complete(b,op,"Admin");});
                second.get(5,TimeUnit.SECONDS);release.countDown();first.get(5,TimeUnit.SECONDS);
                assertThat(lifecycle.snapshot(a)).isEqualTo(new DeviceTrustLifecycle.Snapshot(0,false));
                assertThat(lifecycle.snapshot(b)).isEqualTo(new DeviceTrustLifecycle.Snapshot(1,false));
            }finally{release.countDown();pool.shutdownNow();}
        }
        @Test void concurrentOperationUuidReuseCommitsOnlyOneExactOwner() throws Exception {
            String a=subject("race-Alice"),b=subject("race-alice");fresh(a,b);lifecycle.generation(a);lifecycle.generation(b);
            UUID operation=UUID.randomUUID();var start=new CountDownLatch(1);var pool=Executors.newFixedThreadPool(2);
            try {
                List<Future<Boolean>> results=new ArrayList<>();
                for(String s:List.of(a,b))results.add(pool.submit(()->{start.await();try{lifecycle.revoke(s,operation,"Admin");return true;}catch(DeviceTrustRejectedException|org.springframework.dao.DataAccessException ex){return false;}}));
                start.countDown();int committed=0;for(var result:results)if(result.get(10,TimeUnit.SECONDS))committed++;
                assertThat(committed).isEqualTo(1);
                var rows=jdbc.queryForList("SELECT subject_id FROM device_trust_revocations WHERE operation_id=?",operation.toString());assertThat(rows).hasSize(1);
                String winner=rows.get(0).get("subject_id").toString(),loser=winner.equals(a)?b:a;
                assertThat(lifecycle.snapshot(winner)).isEqualTo(new DeviceTrustLifecycle.Snapshot(1,true));
                assertThat(lifecycle.snapshot(loser)).isEqualTo(new DeviceTrustLifecycle.Snapshot(0,false));
            }finally{pool.shutdownNow();}
        }
        @Test void securityRevocationDoesNotRevokeOtherSubjectOrGrantTrust() {
            String a=subject("security-Alice"),b=subject("security-alice");fresh(a,b);lifecycle.generation(a);String device="device";
            var revoked=new KnownDeviceEntity(a,hasher.hash(a,device),SubjectIdentityMySqlSupport.NOW.get().minusSeconds(1));revoked.revoke(SubjectIdentityMySqlSupport.NOW.get());devices.saveAndFlush(revoked);
            registration.trustAfterMfa(b,device,0);UUID operation=UUID.randomUUID();lifecycle.revoke(a,operation,"Admin");lifecycle.complete(a,operation,"Admin");
            assertThat(status(a,device)).isEqualTo("REVOKED");assertThat(status(b,device)).isEqualTo("TRUSTED");
            assertThat(lifecycle.snapshot(b)).isEqualTo(new DeviceTrustLifecycle.Snapshot(0,false));
            assertThatThrownBy(()->registration.trustAfterMfa(a,device,1)).isInstanceOf(DeviceTrustRejectedException.class);
            assertThat(devices.findAllBySubjectId(a)).singleElement().extracting(KnownDeviceEntity::getRevocationReason).isEqualTo("SECURITY");
        }
    }
}
