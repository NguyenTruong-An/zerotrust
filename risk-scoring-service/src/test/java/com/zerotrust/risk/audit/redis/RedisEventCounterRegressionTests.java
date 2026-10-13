package com.zerotrust.risk.audit.redis;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.assertj.core.api.SoftAssertions;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.RedisCallback;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

/** Native Redis oracle: actual key state/absolute expiry, native INCR and fixed integer boundaries. */
@EnabledIfSystemProperty(named="qa.redis.audit",matches="true")
class RedisEventCounterRegressionTests extends RedisAuditSupport {
    static final String SUBJECT="subject1",IP="203.0.113.10";
    @ParameterizedTest @CsvSource({
        "subject,invalid","ip,invalid","subject,list","ip,list",
        "subject,9223372036854775807","ip,9223372036854775807",
        "subject,9223372036854775808","ip,9223372036854775808",
        "subject,-9223372036854775809","ip,-9223372036854775809",
        "subject,01","ip,01","subject,+1","ip,+1","subject,1.0","ip,1.0","subject,-0","ip,-0"})
    void rejectedCounterDoesNotChangeHealthyCounterOrExpiry(String scope,String value) {
        track("retry",SUBJECT,IP);String bad=scope.equals("subject")?subject(SUBJECT):ip(IP),healthy=scope.equals("subject")?ip(IP):subject(SUBJECT);
        seed(healthy,"5");primary.template.expire(healthy,Duration.ofSeconds(30));
        if(value.equals("list")){primary.template.opsForList().rightPush(bad,"bad-type");primary.template.expire(bad,Duration.ofSeconds(40));}else seed(bad,value);
        State badBefore=state(bad),healthyBefore=state(healthy),eventBefore=state(event("retry"));
        // Redis's own command independently confirms that this representation cannot be incremented.
        assertThatThrownBy(()->primary.template.opsForValue().increment(bad)).isInstanceOf(DataAccessException.class);
        Throwable error=catchThrowable(()->store().recordFailure("retry",SUBJECT,IP));
        State badAfter=state(bad),healthyAfter=state(healthy),eventAfter=state(event("retry"));
        seed(bad,"0");boolean retry=store().recordFailure("retry",SUBJECT,IP),duplicate=store().recordFailure("retry",SUBJECT,IP);
        evidence("BEFORE bad="+badBefore+" healthy="+healthyBefore+" event="+eventBefore+" AFTER bad="+badAfter+" healthy="+healthyAfter+" event="+eventAfter+" error="+(error==null?"none":rootCause(error))+" retry="+retry+" duplicate="+duplicate+" repaired="+state(bad)+" healthyFinal="+state(healthy));
        SoftAssertions s=new SoftAssertions();s.assertThat(error).isInstanceOf(DataAccessException.class);
        same(s,badBefore,badAfter);same(s,healthyBefore,healthyAfter);same(s,eventBefore,eventAfter);
        s.assertThat(retry).isTrue();s.assertThat(duplicate).isFalse();s.assertThat(get(bad)).isEqualTo("1");s.assertThat(get(healthy)).isEqualTo("6");s.assertAll();
    }
    @ParameterizedTest @CsvSource({
        "subject,0","ip,0","subject,9007199254740991","ip,9007199254740991",
        "subject,9007199254740992","ip,9007199254740992","subject,9007199254740993","ip,9007199254740993",
        "subject,9223372036854775806","ip,9223372036854775806"})
    void validIntegerBoundariesUseExactRedisValues(String scope,String value) {
        track("boundary",SUBJECT,IP);String key=scope.equals("subject")?subject(SUBJECT):ip(IP);seed(key,value);State before=state(key);
        assertThat(store().recordFailure("boundary",SUBJECT,IP)).isTrue();
        assertThat(get(key)).isEqualTo(Long.toString(Math.addExact(Long.parseLong(value),1)));
        if(!value.equals("0"))assertThat(state(key).expiry()).isEqualTo(before.expiry());
        assertThat(store().recordFailure("boundary",SUBJECT,IP)).isFalse();
        if(value.equals("9223372036854775806")){
            track("overflow-next",SUBJECT,IP);State a=state(subject(SUBJECT)),b=state(ip(IP));
            assertThatThrownBy(()->store().recordFailure("overflow-next",SUBJECT,IP)).isInstanceOf(DataAccessException.class);
            same(a,state(subject(SUBJECT)));same(b,state(ip(IP)));assertThat(get(event("overflow-next"))).isNull();
        }
    }
    @Test void duplicateEventIdKeepsExistingPayloadContractEvenIfTheNewPayloadCounterIsInvalid() {
        track("same",SUBJECT,IP);track("same","other","203.0.113.11");
        assertThat(store().recordFailure("same",SUBJECT,IP)).isTrue();State marker=state(event("same"));
        primary.template.opsForList().rightPush(subject("other"),"bad-type");State bad=state(subject("other"));
        assertThat(store().recordFailure("same","other","203.0.113.11")).isFalse();
        same(marker,state(event("same")));same(bad,state(subject("other")));assertThat(get(ip("203.0.113.11"))).isNull();counters(SUBJECT,IP,1,1);
    }
    @ParameterizedTest @ValueSource(booleans={true,false})
    void independentClientsHaveNoLostOrDuplicateIncrements(boolean sameEvent) throws Exception {
        for(int i=0;i<8;i++)track(sameEvent?"same":"event"+i,SUBJECT,IP);
        assertThat(concurrent(8,(i,c)->store(c).recordFailure(sameEvent?"same":"event"+i,SUBJECT,IP))).isEqualTo(sameEvent?1:8);
        counters(SUBJECT,IP,sameEvent?1:8,sameEvent?1:8);
    }
    @Test void concurrentFailuresRemainRetryableAfterOnlyTheBadKeyIsRepaired() throws Exception {
        for(int i=0;i<8;i++)track("event"+i,SUBJECT,IP);seed(subject(SUBJECT),"5");seed(ip(IP),"invalid");State before=state(subject(SUBJECT));
        assertThat(concurrent(8,(i,c)->{assertThatThrownBy(()->store(c).recordFailure("event"+i,SUBJECT,IP)).isInstanceOf(DataAccessException.class);return false;})).isZero();
        same(before,state(subject(SUBJECT)));for(int i=0;i<8;i++)assertThat(get(event("event"+i))).isNull();
        seed(ip(IP),"0");assertThat(concurrent(8,(i,c)->store(c).recordFailure("event"+i,SUBJECT,IP))).isEqualTo(8);counters(SUBJECT,IP,13,8);
    }
    @Test void fixedWindowExpiryAndDedupLifetimeRemainIndependent() {
        properties.setFailureWindow(Duration.ofSeconds(1));properties.setEventDeduplicationTtl(Duration.ofSeconds(3));track("old",SUBJECT,IP);track("new",SUBJECT,IP);
        assertThat(store().recordFailure("old",SUBJECT,IP)).isTrue();State a=state(subject(SUBJECT)),b=state(event("old"));
        assertThat(store().recordFailure("new",SUBJECT,IP)).isTrue();assertThat(store().recordFailure("old",SUBJECT,IP)).isFalse();
        assertThat(state(subject(SUBJECT)).expiry()).isEqualTo(a.expiry());assertThat(state(event("old")).expiry()).isEqualTo(b.expiry());
        await().atMost(Duration.ofSeconds(4)).until(()->get(subject(SUBJECT))==null&&get(ip(IP))==null);
        assertThat(store().recordFailure("old",SUBJECT,IP)).isFalse();counters(SUBJECT,IP,0,0);
        await().atMost(Duration.ofSeconds(4)).until(()->get(event("old"))==null);
        assertThat(store().recordFailure("old",SUBJECT,IP)).isTrue();counters(SUBJECT,IP,1,1);
    }
    @Test void aLostReplyAfterSuccessfulLuaDoesNotDoubleCountOnRetry() throws Exception {
        track("lost",SUBJECT,IP);
        try(var proxy=new RedisFaultProxy(RedisFaultProxy.Mode.DROP_COMMITTED_REPLY,properties.getKeyPrefix())){
            Client c=client(proxy.port(),Duration.ofMillis(600));proxy.arm();
            assertThatThrownBy(()->store(c).recordFailure("lost",SUBJECT,IP)).isInstanceOf(DataAccessException.class);
            assertThat(proxy.intercepted.await(2,TimeUnit.SECONDS)).isTrue();assertThat(proxy.reply).isEqualTo("Redis actual integer 1");
            counters(SUBJECT,IP,1,1);assertThat(store().recordFailure("lost",SUBJECT,IP)).isFalse();counters(SUBJECT,IP,1,1);assertThat(proxy.failure).isNull();
        }
    }
    @ParameterizedTest @ValueSource(strings={"subject","ip"})
    void corruptedHistoryStaysIncompleteUntilAnExplicitRepairAndNeverAllowsTheFailedEvent(String scope) {
        track("risk",SUBJECT,IP);String bad=scope.equals("subject")?subject(SUBJECT):ip(IP);seed(bad,"invalid");
        assertThatThrownBy(()->store().recordFailure("risk",SUBJECT,IP)).isInstanceOf(DataAccessException.class);
        var result=RedisRiskHarness.evaluate(store());assertThat(result.dataStatus()).isEqualTo(com.zerotrust.risk.domain.RiskDataStatus.INCOMPLETE);
        assertThat(result.decision()).isEqualTo(com.zerotrust.risk.domain.RiskDecision.STEP_UP_MFA);assertThat(get(event("risk"))).isNull();
        seed(bad,"0");assertThat(store().recordFailure("risk",SUBJECT,IP)).isTrue();counters(SUBJECT,IP,1,1);
    }
    @ParameterizedTest @CsvSource({"window,0","dedup,0","window,9223372036854775807","dedup,9223372036854775807"})
    void invalidExpiryArgumentsDoNotMutateEventOrCounters(String setting,long seconds) {
        track("ttl-error",SUBJECT,IP);seed(subject(SUBJECT),"5");seed(ip(IP),"0");State a=state(subject(SUBJECT)),b=state(ip(IP));
        if(setting.equals("window"))properties.setFailureWindow(Duration.ofSeconds(seconds));else properties.setEventDeduplicationTtl(Duration.ofSeconds(seconds));
        assertThatThrownBy(()->store().recordFailure("ttl-error",SUBJECT,IP)).isInstanceOf(DataAccessException.class);
        same(a,state(subject(SUBJECT)));same(b,state(ip(IP)));assertThat(get(event("ttl-error"))).isNull();
    }
    record State(String type,String value,long expiry,long pttl){}
    State state(String key){
        String type=primary.template.type(key).code(),value=type.equals("string")?get(key):type.equals("list")?primary.template.opsForList().range(key,0,-1).toString():"<"+type+">";
        long expiry=Objects.requireNonNull(primary.template.execute((RedisCallback<Long>)c->{
            @SuppressWarnings("unchecked")var commands=(io.lettuce.core.api.async.RedisAsyncCommands<byte[],byte[]>)c.getNativeConnection();
            return commands.pexpiretime(key.getBytes(StandardCharsets.UTF_8)).toCompletableFuture().join();
        }));return new State(type,value,expiry,ttl(key));
    }
    void same(State a,State b){assertThat(b.type()).isEqualTo(a.type());assertThat(b.value()).isEqualTo(a.value());assertThat(b.expiry()).isEqualTo(a.expiry());}
    void same(SoftAssertions s,State a,State b){s.assertThat(b.type()).isEqualTo(a.type());s.assertThat(b.value()).isEqualTo(a.value());s.assertThat(b.expiry()).isEqualTo(a.expiry());}
    interface Request{boolean apply(int index,Client client);}
    long concurrent(int n,Request request) throws Exception {
        var connections=new ArrayList<Client>();for(int i=0;i<n;i++)connections.add(client());var ids=connections.stream().map(Client::id).toList();assertThat(new HashSet<>(ids)).hasSize(n);
        var barrier=new CyclicBarrier(n+1);var pool=Executors.newFixedThreadPool(n);
        try{var results=new ArrayList<Future<Boolean>>();for(int i=0;i<n;i++){int index=i;results.add(pool.submit(()->{barrier.await(5,TimeUnit.SECONDS);return request.apply(index,connections.get(index));}));}
            barrier.await(5,TimeUnit.SECONDS);long accepted=0;for(var f:results)if(f.get(8,TimeUnit.SECONDS))accepted++;evidence("INDEPENDENT clients="+ids+" accepted="+accepted);return accepted;
        }finally{pool.shutdownNow();assertThat(pool.awaitTermination(5,TimeUnit.SECONDS)).isTrue();}
    }
}
