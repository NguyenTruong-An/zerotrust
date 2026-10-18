package com.zerotrust.risk.service;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;

@EnabledIfSystemProperty(named="postfix03b.native",matches="APPROVED")
@SpringBootTest(properties={"spring.datasource.url=${PF03B_MYSQL_URL}","spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver",
        "spring.datasource.username=pf03b_app","spring.datasource.password=${PF03B_MYSQL_PASSWORD}","spring.jpa.hibernate.ddl-auto=validate","spring.flyway.enabled=false",
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration,org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration"})
@ActiveProfiles("test")
@ContextConfiguration(initializers=TimestampMySqlSupport.class)
@Import(TimestampLifecyclePrecisionContract.TimeConfig.class)
class TimestampLifecyclePrecisionMySqlTests extends TimestampLifecyclePrecisionContract {
    @BeforeEach void nativeBefore() throws Exception {TimestampMySqlSupport.before();}
    @AfterEach void nativeAfter() throws Exception {TimestampMySqlSupport.after();}

    @Test void repeatableReadSnapshotStillRevokesRegistrationCommittedAfterSnapshot() throws Exception {
        String s=subject(),d=device();java.util.UUID op=java.util.UUID.randomUUID();NOW.set(at(123456789));
        lifecycle.generation(s);
        var observed=new java.util.concurrent.CountDownLatch(1);var release=new java.util.concurrent.CountDownLatch(1);
        var pool=java.util.concurrent.Executors.newSingleThreadExecutor();
        var tx=new org.springframework.transaction.support.TransactionTemplate(transactions);
        tx.setIsolationLevel(org.springframework.transaction.TransactionDefinition.ISOLATION_REPEATABLE_READ);
        try {
            var revoker=pool.submit(()->tx.executeWithoutResult(status->{
                org.assertj.core.api.Assertions.assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM known_devices WHERE subject_id=?",Long.class,s)).isZero();
                observed.countDown();
                try {if(!release.await(15,java.util.concurrent.TimeUnit.SECONDS))throw new IllegalStateException("snapshot latch timeout");}
                catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException(e);}
                lifecycle.revoke(s,op,"Admin");
            }));
            org.assertj.core.api.Assertions.assertThat(observed.await(10,java.util.concurrent.TimeUnit.SECONDS)).isTrue();
            registration.trustAfterMfa(s,d,0);release.countDown();revoker.get(15,java.util.concurrent.TimeUnit.SECONDS);
            revoked(s,d,op,at(123457000));completeAndReplay(s,op);record("repeatable_read_current_read",s,NOW.get());
        } finally {release.countDown();pool.shutdownNow();}
    }
}
