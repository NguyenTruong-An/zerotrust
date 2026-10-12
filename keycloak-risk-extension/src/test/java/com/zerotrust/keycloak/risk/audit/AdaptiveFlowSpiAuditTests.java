package com.zerotrust.keycloak.risk.audit;

import com.zerotrust.keycloak.risk.authenticator.RiskStepUpCondition;
import com.zerotrust.keycloak.risk.context.CookieDeviceIdResolver;
import com.zerotrust.keycloak.risk.policy.RiskAuthenticationNotes;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.NewCookie;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.keycloak.authentication.AuthenticationProcessor;
import java.util.*;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static com.zerotrust.keycloak.risk.audit.SpiAuditFixture.*;

@EnabledIfSystemProperty(named="qa.spi.audit",matches="true")
class AdaptiveFlowSpiAuditTests {
    @TestFactory Stream<DynamicTest> decisionsAndAllRepeatedTransitions(){
        List<DynamicTest> tests=new ArrayList<>();
        for(String before:List.of("ALLOW","STEP_UP_MFA","DENY"))for(String after:List.of("ALLOW","STEP_UP_MFA","DENY")){
            tests.add(DynamicTest.dynamicTest(before+" -> "+after,()->{try(var f=new SpiAuditFixture()){
                f.decision(before,7L,true);f.evaluator().authenticate(f.context);
                f.decision(after,8L,false);f.evaluator().authenticate(f.context);
                assertEquals(after,f.notes.get(RiskAuthenticationNotes.DECISION));
                assertEquals(before.equals("DENY")?0:1,(f.successes.get()-(after.equals("DENY")?0:1)));
                assertEquals((before.equals("DENY")?1:0)+(after.equals("DENY")?1:0),f.denials.get());
                assertEquals(after.equals("STEP_UP_MFA"),RiskStepUpCondition.INSTANCE.matchCondition(f.context));
                assertNull(f.notes.get(RiskAuthenticationNotes.FAILURE_TYPE));
                f.registration().authenticate(f.context);
                if(after.equals("STEP_UP_MFA")){
                    assertEquals(1,f.at(REGISTER).size());assertEquals(8,((Number)f.at(REGISTER).get(0).json().get("trustGeneration")).intValue());
                    assertEquals(1,f.emitted.size());
                }else{assertTrue(f.at(REGISTER).isEmpty());assertTrue(f.emitted.isEmpty());}
                assertRegistrationNotesConsumed(f);
            }}));
        }
        return tests.stream();
    }
    @TestFactory Stream<DynamicTest> generationsFenceEligibility(){
        return Stream.of("null","-1","0","9223372036854775807").map(value->DynamicTest.dynamicTest("generation="+value,()->{try(var f=new SpiAuditFixture()){
            Long generation=value.equals("null")?null:Long.valueOf(value);
            f.decision("STEP_UP_MFA",generation,false);f.evaluator().authenticate(f.context);
            boolean eligible=generation!=null&&generation>=0;
            assertEquals(eligible,Boolean.parseBoolean(f.notes.get(RiskAuthenticationNotes.TRUST_DEVICE_ELIGIBLE)));
            assertTrue(RiskStepUpCondition.INSTANCE.matchCondition(f.context));
            f.registration().authenticate(f.context);
            assertEquals(eligible?1:0,f.at(REGISTER).size());assertEquals(eligible?1:0,f.emitted.size());
            if(eligible)assertEquals(generation.longValue(),((Number)f.at(REGISTER).get(0).json().get("trustGeneration")).longValue());
        }}));
    }
    @TestFactory Stream<DynamicTest> enrollmentRequiresExactMandatoryProvider(){
        return Stream.of("no-action","pending-none","pending-otp","pending-recovery","pending-both","disabled","missing","wrong-provider")
            .map(mode->DynamicTest.dynamicTest(mode,()->{try(var f=new SpiAuditFixture()){
                f.decision("STEP_UP_MFA",4L,true);f.evaluator().authenticate(f.context);f.oldCookie();
                if(!mode.equals("no-action"))f.requiredActions.add("CONFIGURE_TOTP");
                when(f.credentials.isConfiguredFor("otp")).thenReturn(mode.equals("pending-otp")||mode.equals("pending-both"));
                when(f.credentials.isConfiguredFor("recovery-authn-codes")).thenReturn(mode.equals("pending-recovery")||mode.equals("pending-both"));
                if(mode.equals("disabled"))f.totpAction.setEnabled(false);
                if(mode.equals("missing"))when(f.realm.getRequiredActionProviderByAlias("CONFIGURE_TOTP")).thenReturn(null);
                if(mode.equals("wrong-provider"))f.totpAction.setProviderId("qa-unrelated-provider");
                assertEquals(!mode.equals("pending-none"),RiskStepUpCondition.INSTANCE.matchCondition(f.context));
                f.registration().authenticate(f.context);
                if(mode.equals("no-action")){assertEquals(1,f.at(REGISTER).size());assertEquals(2592000,f.emitted.get(0).getMaxAge());}
                else{assertTrue(f.at(REGISTER).isEmpty());assertEquals(1,f.emitted.size());assertEquals(0,f.emitted.get(0).getMaxAge());}
                assertRegistrationNotesConsumed(f);
            }}));
    }
    @TestFactory Stream<DynamicTest> registrationRequires204BeforeIssuingCookie(){
        return Stream.of(204,200,202,401,403,409,500).map(status->DynamicTest.dynamicTest("registration HTTP "+status,()->{try(var f=new SpiAuditFixture()){
            f.oldCookie();f.decision("STEP_UP_MFA",3L,false);f.evaluator().authenticate(f.context);
            f.handlers.put(REGISTER,c->Reply.empty(status));f.registration().authenticate(f.context);
            assertEquals(status==401?2:1,f.at(REGISTER).size());
            assertEquals(status==204||status==409?1:0,f.emitted.size());
            if(status==204){assertEquals("old-device-qa02a",f.emitted.get(0).getValue());assertEquals(2592000,f.emitted.get(0).getMaxAge());
                assertTrue(f.order.indexOf("wire:"+REGISTER)<f.order.indexOf("cookie"));
            }
            if(status==409){assertEquals("",f.emitted.get(0).getValue());assertEquals(0,f.emitted.get(0).getMaxAge());}
            assertEquals(0,f.denials.get());assertEquals(2,f.successes.get());assertRegistrationNotesConsumed(f);
            f.registration().authenticate(f.context);assertEquals(status==401?2:1,f.at(REGISTER).size());
        }}));
    }
    @TestFactory Stream<DynamicTest> invalidRegistrationNotesNeverReachWire(){
        return Stream.of("missing-generation","negative-generation","overflow-generation","not-number","missing-config","removed-config")
            .map(mode->DynamicTest.dynamicTest(mode,()->{try(var f=new SpiAuditFixture()){
                f.decision("STEP_UP_MFA",0L,false);f.evaluator().authenticate(f.context);
                switch(mode){
                    case "missing-generation"->f.notes.remove(RiskAuthenticationNotes.TRUST_GENERATION);
                    case "negative-generation"->f.notes.put(RiskAuthenticationNotes.TRUST_GENERATION,"-1");
                    case "overflow-generation"->f.notes.put(RiskAuthenticationNotes.TRUST_GENERATION,"9223372036854775808");
                    case "not-number"->f.notes.put(RiskAuthenticationNotes.TRUST_GENERATION,"0.0");
                    case "missing-config"->f.notes.remove(RiskAuthenticationNotes.EVALUATOR_CONFIG_ID);
                    case "removed-config"->f.configs.clear();
                }
                f.registration().authenticate(f.context);assertTrue(f.at(REGISTER).isEmpty());assertTrue(f.emitted.isEmpty());
                assertRegistrationNotesConsumed(f);assertEquals(0,f.denials.get());
            }}));
    }
    @Test void resetRotationAndRepeatHaveSingleRegistration()throws Exception{try(var f=new SpiAuditFixture()){
        f.oldCookie();f.decision("STEP_UP_MFA",11L,true);f.evaluator().authenticate(f.context);
        var registration=f.registration();registration.authenticate(f.context);registration.authenticate(f.context);
        assertEquals(1,f.at(REGISTER).size());var payload=f.at(REGISTER).get(0).json();
        assertEquals(SUBJECT,payload.get("subjectId"));assertEquals(11,((Number)payload.get("trustGeneration")).intValue());
        String generated=(String)payload.get("deviceId");assertNotEquals("old-device-qa02a",generated);assertEquals(43,generated.length());
        assertEquals(1,f.emitted.size());NewCookie cookie=f.emitted.get(0);
        assertEquals(generated,cookie.getValue());assertEquals("/realms/qa02a/",cookie.getPath());
        assertTrue(cookie.isSecure());assertTrue(cookie.isHttpOnly());assertEquals(NewCookie.SameSite.LAX,cookie.getSameSite());
        assertEquals(2592000,cookie.getMaxAge());assertRegistrationNotesConsumed(f);
    }}
    @TestFactory Stream<DynamicTest> cookieInputBoundaries(){
        return Stream.of("absent","7-bytes","8-bytes","255-bytes","256-bytes","space","unicode","legal-symbols")
            .map(mode->DynamicTest.dynamicTest(mode,()->{try(var f=new SpiAuditFixture()){
                String value=switch(mode){case "absent"->null;case "7-bytes"->"x".repeat(7);case "8-bytes"->"x".repeat(8);case "255-bytes"->"x".repeat(255);case "256-bytes"->"x".repeat(256);case "space"->"device id";case "unicode"->"device-đ";default->"device._~-";};
                boolean valid=Set.of("8-bytes","255-bytes","legal-symbols").contains(mode);
                if(value!=null)f.cookies.put(CookieDeviceIdResolver.COOKIE_NAME,new Cookie(CookieDeviceIdResolver.COOKIE_NAME,value));
                f.evaluator().authenticate(f.context);assertEquals(valid?value:null,f.at(EVALUATE).get(0).json().get("deviceId"));
                assertEquals(1,f.successes.get());assertEquals(0,f.denials.get());
            }}));
    }
    @Test void keycloakStaticResetClearsStaleRiskEligibility()throws Exception{try(var f=new SpiAuditFixture()){
        f.decision("STEP_UP_MFA",2L,true);f.evaluator().authenticate(f.context);assertFalse(f.notes.isEmpty());
        AuthenticationProcessor.resetFlow(f.auth,"authenticate");
        assertNull(f.notes.get(RiskAuthenticationNotes.TRUST_DEVICE_ELIGIBLE));assertNull(f.notes.get(RiskAuthenticationNotes.TRUST_GENERATION));
        f.registration().authenticate(f.context);assertTrue(f.at(REGISTER).isEmpty());assertTrue(f.emitted.isEmpty());
        // Executes only Keycloak's static reset helper, not its authentication engine.
    }}
    @TestFactory Stream<DynamicTest> extractorPreservesRiskInputsForKnownBugReachability(){
        return Stream.of("mixed-ipv6","hex-ipv6","padded-subject").map(mode->DynamicTest.dynamicTest(mode,()->{try(var f=new SpiAuditFixture()){
            String subject=mode.equals("padded-subject")?" "+SUBJECT+" ":SUBJECT;
            String ip=mode.equals("mixed-ipv6")?"2001:db8::192.0.2.1":mode.equals("hex-ipv6")?"2001:db8::c000:201":"203.0.113.22";
            when(f.user.getId()).thenReturn(subject);when(f.connection.getRemoteAddr()).thenReturn(ip);
            f.handlers.put(EVALUATE,c->Reply.json(200,evaluation("ALLOW",0L,false).replace(SUBJECT,subject)));
            f.evaluator().authenticate(f.context);var payload=f.at(EVALUATE).get(0).json();
            assertEquals(subject,payload.get("subjectId"));assertEquals(ip,payload.get("ipAddress"));assertEquals(SESSION,payload.get("authenticationSessionId"));
            assertEquals("qa-browser",payload.get("clientId"));assertEquals("QA02A/1.0",payload.get("userAgent"));
            assertEquals(1,f.successes.get());assertEquals(0,f.denials.get());
            // Boundary characterization only; no assertion that a real Keycloak engine emits padded IDs.
        }}));
    }
    static void assertRegistrationNotesConsumed(SpiAuditFixture f){
        for(String key:List.of(RiskAuthenticationNotes.TRUST_DEVICE_ELIGIBLE,RiskAuthenticationNotes.TRUST_GENERATION,RiskAuthenticationNotes.ROTATE_DEVICE,RiskAuthenticationNotes.EVALUATOR_CONFIG_ID))assertFalse(f.notes.containsKey(key),key);
    }
}
