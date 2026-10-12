package com.zerotrust.keycloak.risk.audit;

import com.zerotrust.keycloak.risk.authenticator.RiskStepUpCondition;
import com.zerotrust.keycloak.risk.client.*;
import com.zerotrust.keycloak.risk.config.RiskAuthenticatorConfigResolver;
import com.zerotrust.keycloak.risk.policy.RiskAuthenticationNotes;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;
import static com.zerotrust.keycloak.risk.audit.SpiAuditFixture.*;

@EnabledIfSystemProperty(named="qa.spi.audit",matches="true")
class TransportSpiAuditTests {
    @TestFactory Stream<DynamicTest> riskErrorsHonorModeAndClearPreviousTrustEligibility(){
        return Stream.of("DENY","STEP_UP_MFA").flatMap(mode->Stream.of("403","500","bad-json","wrong-subject","wrong-session","unknown-decision","html","oversize")
            .map(fault->DynamicTest.dynamicTest(mode+"/"+fault,()->{try(var f=new SpiAuditFixture()){
                f.decision("STEP_UP_MFA",9L,true);var authenticator=f.evaluator();authenticator.authenticate(f.context);
                f.config.getConfig().put("failureMode",mode);
                Reply reply=switch(fault){
                    case "403","500"->Reply.empty(Integer.parseInt(fault));
                    case "bad-json"->Reply.json(200,"{broken");
                    case "wrong-subject"->Reply.json(200,evaluation("ALLOW",9L,false).replace(SUBJECT,"2a000000-0000-4000-8000-000000000009"));
                    case "wrong-session"->Reply.json(200,evaluation("ALLOW",9L,false).replace(SESSION,"qa-other-tab"));
                    case "unknown-decision"->Reply.json(200,evaluation("ALLOW",9L,false).replace("ALLOW","NEW_UNKNOWN"));
                    case "html"->new Reply(200,"<html/>","text/html",null);
                    default->Reply.json(200,"x".repeat(65537));
                };
                f.handlers.put(EVALUATE,c->reply);authenticator.authenticate(f.context);
                assertEquals(mode.equals("DENY")?"DENY":"STEP_UP_MFA",f.notes.get(RiskAuthenticationNotes.DECISION));
                assertEquals(mode.equals("DENY")?1:0,f.denials.get());
                assertEquals(mode.equals("STEP_UP_MFA"),RiskStepUpCondition.INSTANCE.matchCondition(f.context));
                assertEquals(fault.equals("403")||fault.equals("500")?"HTTP_ERROR":"INVALID_RESPONSE",f.notes.get(RiskAuthenticationNotes.FAILURE_TYPE));
                AdaptiveFlowSpiAuditTests.assertRegistrationNotesConsumed(f);
                f.registration().authenticate(f.context);assertTrue(f.at(REGISTER).isEmpty());assertTrue(f.emitted.isEmpty());
                assertEquals(1,f.at(TOKEN).size());assertEquals(2,f.at(EVALUATE).size());
            }})));
    }
    @Test void one401RetryRefreshesTokenAndPreservesRequestBody()throws Exception{try(var f=new SpiAuditFixture()){
        AtomicInteger attempts=new AtomicInteger();f.handlers.put(EVALUATE,c->attempts.incrementAndGet()==1?Reply.empty(401):Reply.json(200,evaluation("STEP_UP_MFA",4L,false)));
        f.evaluator().authenticate(f.context);
        assertEquals(2,f.at(TOKEN).size());assertEquals(2,f.at(EVALUATE).size());
        assertEquals(f.at(EVALUATE).get(0).body(),f.at(EVALUATE).get(1).body());
        assertTrue(!Objects.equals(f.at(EVALUATE).get(0).authorization(),f.at(EVALUATE).get(1).authorization()),"Rejected token must be replaced");
        assertEquals("STEP_UP_MFA",f.notes.get(RiskAuthenticationNotes.DECISION));assertEquals("4",f.notes.get(RiskAuthenticationNotes.TRUST_GENERATION));
    }}
    @Test void repeated401StopsAfterOneRetryAndNeverRegisters()throws Exception{try(var f=new SpiAuditFixture()){
        f.handlers.put(EVALUATE,c->Reply.empty(401));f.evaluator().authenticate(f.context);
        assertEquals(2,f.at(EVALUATE).size());assertEquals(2,f.at(TOKEN).size());assertEquals(1,f.denials.get());
        assertEquals("HTTP_ERROR",f.notes.get(RiskAuthenticationNotes.FAILURE_TYPE));
        f.registration().authenticate(f.context);assertTrue(f.at(REGISTER).isEmpty());assertTrue(f.emitted.isEmpty());
    }}
    @Test void clientCredentialsEncodingAndCachingAreActualHttp()throws Exception{try(var f=new SpiAuditFixture()){
        var a=f.evaluator();a.authenticate(f.context);a.authenticate(f.context);
        assertEquals(1,f.at(TOKEN).size());var token=f.at(TOKEN).get(0);
        assertEquals("POST",token.method());assertEquals("grant_type=client_credentials",token.body());
        String expected="Basic "+Base64.getEncoder().encodeToString((URLEncoder.encode("qa:caller+name",StandardCharsets.UTF_8)+":"+URLEncoder.encode("fixture: secret+only",StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8));
        assertTrue(expected.equals(token.authorization()),"Basic credential encoding must form-encode each component");
        assertTrue(f.at(EVALUATE).stream().allMatch(c->c.authorization()!=null&&c.authorization().startsWith("Bearer ")),"Bearer header missing");
        assertTrue(f.at(EVALUATE).stream().noneMatch(c->c.body().contains("secret")||c.body().contains("access_token")),"Credential leaked into evaluation JSON");
    }}
    @TestFactory Stream<DynamicTest> invalidTokenResponseStopsBeforeRiskRequest(){
        return Stream.of("missing-token","fractional-expiry","wrong-type","token-whitespace","token-403","bad-json").map(mode->DynamicTest.dynamicTest(mode,()->{try(var f=new SpiAuditFixture()){
            String body=switch(mode){case "missing-token"->"{\"token_type\":\"Bearer\",\"expires_in\":30}";case "fractional-expiry"->"{\"access_token\":\"qa\",\"token_type\":\"Bearer\",\"expires_in\":0.5}";case "wrong-type"->"{\"access_token\":\"qa\",\"token_type\":\"MAC\",\"expires_in\":30}";case "token-whitespace"->"{\"access_token\":\"qa bad\",\"token_type\":\"Bearer\",\"expires_in\":30}";default->"{broken";};
            f.handlers.put(TOKEN,c->Reply.json(mode.equals("token-403")?403:200,body));f.evaluator().authenticate(f.context);
            assertTrue(f.at(EVALUATE).isEmpty());assertEquals(1,f.at(TOKEN).size());assertEquals(1,f.denials.get());
            f.registration().authenticate(f.context);assertTrue(f.at(REGISTER).isEmpty());assertTrue(f.emitted.isEmpty());
        }}));
    }
    @TestFactory Stream<DynamicTest> socketTimeoutHasMeasuredHttpCheckpoint(){
        return Stream.of("DENY","STEP_UP_MFA").map(mode->DynamicTest.dynamicTest("actual socket timeout/"+mode,()->{try(var f=new SpiAuditFixture()){
            f.config.getConfig().put("failureMode",mode);
            CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
            f.handlers.put(EVALUATE,c->{entered.countDown();if(!release.await(4,TimeUnit.SECONDS))throw new IllegalStateException("checkpoint timeout");return Reply.json(200,evaluation("ALLOW",0L,false));});
            ExecutorService worker=Executors.newSingleThreadExecutor();long start=System.nanoTime();
            try{Future<?> task=worker.submit(()->f.evaluator().authenticate(f.context));assertTrue(entered.await(3,TimeUnit.SECONDS));task.get(3,TimeUnit.SECONDS);
                long elapsed=Duration.ofNanos(System.nanoTime()-start).toMillis();assertTrue(elapsed>=400&&elapsed<3000,"Actual elapsed="+elapsed+"ms");
                assertEquals("TIMEOUT",f.notes.get(RiskAuthenticationNotes.FAILURE_TYPE));assertEquals(mode,f.notes.get(RiskAuthenticationNotes.DECISION));
                AdaptiveFlowSpiAuditTests.assertRegistrationNotesConsumed(f);assertEquals(1,f.at(EVALUATE).size());
            }finally{release.countDown();worker.shutdownNow();}
        }}));
    }
    @Test void refusedConnectionIsDeniedWithoutFallbackRealm()throws Exception{try(var f=new SpiAuditFixture()){
        int port;try(ServerSocket reserved=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))){port=reserved.getLocalPort();}
        f.config.getConfig().put("riskServiceBaseUrl","http://127.0.0.1:"+port);
        f.evaluator().authenticate(f.context);assertEquals(1,f.denials.get());assertEquals("CONNECTION_FAILURE",f.notes.get(RiskAuthenticationNotes.FAILURE_TYPE));
        assertTrue(f.at(EVALUATE).isEmpty());AdaptiveFlowSpiAuditTests.assertRegistrationNotesConsumed(f);
        // Closed ephemeral localhost socket: refusal fixture, no storage or operational endpoint.
    }}
    @Test void redirectsCannotForwardBearerOrBasicCredentials()throws Exception{try(var f=new SpiAuditFixture()){
        f.handlers.put(EVALUATE,c->new Reply(307,"","application/json",f.base()+"/sink"));f.evaluator().authenticate(f.context);
        assertEquals(1,f.denials.get());assertTrue(f.at("/sink").isEmpty());assertEquals(1,f.at(EVALUATE).size());
    }}
    @Test void concurrentTokenLoadsUseOneActualTokenRequest()throws Exception{try(var f=new SpiAuditFixture()){
        var cfg=new RiskAuthenticatorConfigResolver().resolve(f.config);var shared=new ServiceTokenCache();
        CountDownLatch ready=new CountDownLatch(6),go=new CountDownLatch(1),entered=new CountDownLatch(1),release=new CountDownLatch(1);
        f.handlers.put(TOKEN,c->{f.tokens.incrementAndGet();entered.countDown();if(!release.await(3,TimeUnit.SECONDS))throw new IllegalStateException("checkpoint timeout");return Reply.json(200,"{\"access_token\":\"qa-concurrent\",\"token_type\":\"Bearer\",\"expires_in\":3600}");});
        ExecutorService workers=Executors.newFixedThreadPool(6);List<Future<String>> tasks=new ArrayList<>();
        try{for(int i=0;i<6;i++)tasks.add(workers.submit(()->{var provider=new ClientCredentialsTokenProvider(f.httpProvider,cfg.serviceTokenConfig(),cfg.clientConfig(),shared);ready.countDown();if(!go.await(3,TimeUnit.SECONDS))throw new IllegalStateException("start timeout");return provider.accessToken();}));
            assertTrue(ready.await(3,TimeUnit.SECONDS));go.countDown();assertTrue(entered.await(3,TimeUnit.SECONDS));release.countDown();
            for(var task:tasks)assertTrue("qa-concurrent".equals(task.get(3,TimeUnit.SECONDS)),"Wrong loaded token");
            assertEquals(1,f.at(TOKEN).size());assertEquals(1,f.tokens.get());
        }finally{release.countDown();go.countDown();workers.shutdownNow();}
    }}
    @Test void trailingJsonIsCharacterizedWithoutInventingStrictParserPolicy()throws Exception{try(var f=new SpiAuditFixture()){
        f.handlers.put(TOKEN,c->Reply.json(200,"{\"access_token\":\"qa-prefix\",\"token_type\":\"Bearer\",\"expires_in\":3600} trailing"));
        f.handlers.put(EVALUATE,c->Reply.json(200,evaluation("ALLOW",0L,false)+" {\"decision\":\"DENY\"}"));
        f.evaluator().authenticate(f.context);
        assertEquals("ALLOW",f.notes.get(RiskAuthenticationNotes.DECISION));assertEquals(1,f.successes.get());assertEquals(0,f.denials.get());
        assertEquals(1,f.at(TOKEN).size());assertEquals(1,f.at(EVALUATE).size());
        // Observed parser extension, not a vulnerability oracle: RFC8259 section9 permits extensions.
    }}
}
