package com.zerotrust.keycloak.risk.audit;

import com.zerotrust.keycloak.risk.config.BrowserFlowRiskConfigLocator;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.keycloak.events.*;
import org.keycloak.models.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;
import static com.zerotrust.keycloak.risk.audit.SpiAuditFixture.*;

@EnabledIfSystemProperty(named="qa.spi.audit",matches="true")
class EventDeliverySpiAuditTests {
    @TestFactory Stream<DynamicTest> supportedEventsDeliverStablePayloadAcross401Retry(){
        return Stream.of(EventType.LOGIN,EventType.LOGIN_ERROR).map(type->DynamicTest.dynamicTest(type.name()+" retry",()->{try(var f=new SpiAuditFixture()){
            String path=type==EventType.LOGIN?SUCCESS:FAILURE;AtomicInteger attempts=new AtomicInteger();
            f.handlers.put(path,c->Reply.empty(attempts.incrementAndGet()==1?401:204));
            var listener=f.listener();listener.onEvent(event(type));
            assertEquals(2,f.at(path).size());assertEquals(2,f.at(TOKEN).size());
            assertEquals(f.at(path).get(0).body(),f.at(path).get(1).body());var payload=f.at(path).get(1).json();
            assertEquals("2a000000-0000-4000-8000-000000000003",payload.get("eventId"));assertEquals(SUBJECT,payload.get("subjectId"));
            if(type==EventType.LOGIN){assertEquals("2026-10-12T01:00:00Z",payload.get("authenticatedAt"));assertEquals("qa-browser",payload.get("clientId"));}
            else assertEquals("203.0.113.22",payload.get("sourceIp"));
            assertEquals(0,f.successes.get());assertEquals(0,f.denials.get());assertTrue(f.emitted.isEmpty());
            listener.onEvent(event(type));assertEquals(3,f.at(path).size());
            assertEquals(f.at(path).get(1).body(),f.at(path).get(2).body());assertEquals(2,f.at(TOKEN).size());
            // Same ID delivery is proven. Redis/MySQL deduplication is not executed here.
        }}));
    }
    @TestFactory Stream<DynamicTest> excludedAndMalformedEventsDoNotUseNetwork(){
        return Stream.of("expired-code","temporary-lockout","logout","other-client","missing-ip","missing-success-user","zero-success-time","null-event")
            .map(mode->DynamicTest.dynamicTest(mode,()->{try(var f=new SpiAuditFixture()){
                Event e=event(mode.startsWith("missing-success")||mode.equals("zero-success-time")?EventType.LOGIN:EventType.LOGIN_ERROR);
                switch(mode){case "expired-code"->e.setError(Errors.EXPIRED_CODE);case "temporary-lockout"->e.setError(Errors.USER_TEMPORARILY_DISABLED);case "logout"->e.setType(EventType.LOGOUT);case "other-client"->e.setClientId("qa-unmonitored");case "missing-ip"->e.setIpAddress(" ");case "missing-success-user"->e.setUserId(null);case "zero-success-time"->e.setTime(0);case "null-event"->e=null;}
                f.listener().onEvent(e);assertTrue(f.calls.isEmpty());assertEquals(0,f.successes.get());assertEquals(0,f.denials.get());
            }}));
    }
    @Test void missingFailureUserStillDeliversIpCounterSignal()throws Exception{try(var f=new SpiAuditFixture()){
        Event e=event(EventType.LOGIN_ERROR);e.setUserId(null);e.setError(Errors.USER_NOT_FOUND);f.listener().onEvent(e);
        assertEquals(1,f.at(FAILURE).size());var body=f.at(FAILURE).get(0).json();assertNull(body.get("subjectId"));assertEquals("203.0.113.22",body.get("sourceIp"));
    }}
    @TestFactory Stream<DynamicTest> eventDeliveryFailuresCannotThrowIntoAuthentication(){
        return Stream.of(403,409,500).map(status->DynamicTest.dynamicTest("delivery HTTP "+status,()->{try(var f=new SpiAuditFixture()){
            f.handlers.put(FAILURE,c->Reply.empty(status));assertDoesNotThrow(()->f.listener().onEvent(event(EventType.LOGIN_ERROR)));
            assertEquals(1,f.at(FAILURE).size());assertEquals(1,f.at(TOKEN).size());assertEquals(0,f.successes.get());assertEquals(0,f.denials.get());assertTrue(f.emitted.isEmpty());
        }}));
    }
    @Test void missingEventIdProducesNewIdsOnRepeatedCallbackCharacterization()throws Exception{try(var f=new SpiAuditFixture()){
        var e=event(EventType.LOGIN_ERROR);e.setId(null);var listener=f.listener();listener.onEvent(e);listener.onEvent(e);
        assertEquals(2,f.at(FAILURE).size());var first=f.at(FAILURE).get(0).json();var second=f.at(FAILURE).get(1).json();
        assertNotEquals(first.get("eventId"),second.get("eventId"));assertEquals(first.get("subjectId"),second.get("subjectId"));assertEquals(first.get("sourceIp"),second.get("sourceIp"));
        // Delivery ambiguity for an ID-less event; normal EventBuilder IDs/runtime callback retries remain 02B.
    }}
    @Test void disabledEvaluatorCannotShadowActiveEventConfiguration()throws Exception{try(var f=new SpiAuditFixture()){
        var stale=f.addConfig("qa-disabled","qa-unmonitored");
        f.executions.put("qa-browser-flow",List.of(evaluator(stale.getId(),10,AuthenticationExecutionModel.Requirement.DISABLED),evaluator("qa-risk",20,AuthenticationExecutionModel.Requirement.REQUIRED)));
        var selected=new BrowserFlowRiskConfigLocator().locate(f.realm);
        System.out.println("QA02A disabled-evaluator expectedConfig=qa-risk actualConfig="+selected.getId());
        assertSame(f.config,selected,"DISABLED evaluator must not supply event configuration");
    }}
    @Test void disabledSubflowCannotShadowActiveEventConfiguration()throws Exception{try(var f=new SpiAuditFixture()){
        f.addConfig("qa-disabled","qa-unmonitored");
        AuthenticationExecutionModel subflow=new AuthenticationExecutionModel();subflow.setId("qa-disabled-subflow");subflow.setAuthenticatorFlow(true);subflow.setFlowId("qa-old-subflow");subflow.setPriority(5);subflow.setRequirement(AuthenticationExecutionModel.Requirement.DISABLED);
        f.executions.put("qa-old-subflow",List.of(evaluator("qa-disabled",10,AuthenticationExecutionModel.Requirement.REQUIRED)));
        f.executions.put("qa-browser-flow",List.of(subflow,evaluator("qa-risk",20,AuthenticationExecutionModel.Requirement.REQUIRED)));
        var selected=new BrowserFlowRiskConfigLocator().locate(f.realm);
        System.out.println("QA02A disabled-subflow expectedConfig=qa-risk actualConfig="+selected.getId());
        assertSame(f.config,selected,"Disabled parent makes its descendant inactive");
    }}
    @Test void disabledEvaluatorMustNotSuppressCountedFailureDelivery()throws Exception{try(var f=new SpiAuditFixture()){
        f.addConfig("qa-disabled","qa-unmonitored");
        f.executions.put("qa-browser-flow",List.of(evaluator("qa-disabled",10,AuthenticationExecutionModel.Requirement.DISABLED),evaluator("qa-risk",20,AuthenticationExecutionModel.Requirement.REQUIRED)));
        // Active evaluator does reach the Risk endpoint, using the qa-browser client.
        f.evaluator().authenticate(f.context);assertEquals(1,f.at(EVALUATE).size());
        f.listener().onEvent(event(EventType.LOGIN_ERROR));
        System.out.println("QA02A delivery activeEvaluations="+f.at(EVALUATE).size()+" expectedFailurePosts=1 actualFailurePosts="+f.at(FAILURE).size());
        assertEquals(1,f.at(FAILURE).size(),"Counted failure of active browser caller must be delivered using active evaluator config");
    }}
    static Event event(EventType type){
        Event e=new Event();e.setType(type);e.setId("2a000000-0000-4000-8000-000000000003");e.setRealmId("qa-realm");e.setClientId("qa-browser");e.setUserId(SUBJECT);e.setIpAddress("203.0.113.22");e.setTime(Instant.parse("2026-10-12T01:00:00Z").toEpochMilli());
        if(type==EventType.LOGIN_ERROR)e.setError(Errors.INVALID_USER_CREDENTIALS);return e;
    }
}
