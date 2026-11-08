package com.zerotrust.keycloak.risk.audit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.sessions.AuthenticationSessionModel;
import static com.zerotrust.keycloak.risk.audit.SpiAuditFixture.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Actual factories/token client/HTTP/enforcement/registration; synthetic Keycloak execution state, not an engine. */
class PublicDemoAdaptiveContractTest {
    @ParameterizedTest @ValueSource(strings={"ALLOW","STEP_UP_MFA","DENY"})
    void currentRiskDecisionDrivesEnforcementAndTrust(String decision)throws Exception{
        try(var f=new SpiAuditFixture()){
            f.decision(decision,7L,false);f.evaluator().authenticate(f.context);
            assertEquals(decision,f.notes.get(com.zerotrust.keycloak.risk.policy.RiskAuthenticationNotes.DECISION));
            assertEquals(1,f.at(EVALUATE).size());
            f.registration().authenticate(f.context);
            assertEquals(decision.equals("STEP_UP_MFA")?1:0,f.at(REGISTER).size());
            assertEquals(decision.equals("STEP_UP_MFA")?1:0,f.emitted.size());
            assertEquals(decision.equals("DENY")?1:0,f.denials.get());
        }
    }

    @Test void http200IncompleteAllowIsDeniedAndDoesNotLeaveOldEligibility()throws Exception{
        try(var f=new SpiAuditFixture()){
            f.decision("STEP_UP_MFA",0L,false);f.evaluator().authenticate(f.context);
            f.handlers.put(EVALUATE,c->Reply.json(200,evaluation("ALLOW",0L,false).replace("COMPLETE","INCOMPLETE")));
            f.evaluator().authenticate(f.context);f.registration().authenticate(f.context);
            assertEquals("DENY",f.notes.get(com.zerotrust.keycloak.risk.policy.RiskAuthenticationNotes.DECISION));
            assertEquals(1,f.denials.get());assertTrue(f.at(REGISTER).isEmpty());assertTrue(f.emitted.isEmpty());
        }
    }

    @Test void mfaChallengeWithoutSuccessCannotProduceTrustOrSuccessfulExecution()throws Exception{
        try(var f=new SpiAuditFixture()){
            f.decision("STEP_UP_MFA",0L,false);f.evaluator().authenticate(f.context);
            when(f.auth.getExecutionStatus()).thenReturn(java.util.Map.of("qa-mfa", AuthenticationSessionModel.ExecutionStatus.CHALLENGED));
            int before=f.successes.get();f.registration().authenticate(f.context);
            assertEquals(before,f.successes.get());assertEquals(1,f.denials.get());
            assertTrue(f.at(REGISTER).isEmpty());assertTrue(f.emitted.isEmpty());
        }
    }

    @Test void switchedSubjectCannotConsumeAnotherSubjectsMfaEligibility()throws Exception{
        try(var f=new SpiAuditFixture()){
            f.decision("STEP_UP_MFA",0L,false);f.evaluator().authenticate(f.context);
            when(f.user.getId()).thenReturn("different-subject");f.registration().authenticate(f.context);
            assertEquals(1,f.denials.get());assertTrue(f.at(REGISTER).isEmpty());assertTrue(f.emitted.isEmpty());
        }
    }

    @Test void registration409DoesNotIssueTrustAndConsumesEligibility()throws Exception{
        try(var f=new SpiAuditFixture()){
            f.oldCookie();f.decision("STEP_UP_MFA",0L,false);f.evaluator().authenticate(f.context);
            f.handlers.put(REGISTER,c->Reply.empty(409));f.registration().authenticate(f.context);f.registration().authenticate(f.context);
            assertEquals(1,f.at(REGISTER).size());assertEquals(1,f.emitted.size());
            assertEquals(0,f.emitted.get(0).getMaxAge());assertEquals("",f.emitted.get(0).getValue());
            assertEquals(0,f.denials.get()); // Current MFA was already successful; no future trust is granted.
        }
    }

    @Test void failedEventDeliveryRemainsBestEffortAndCannotClaimHistoryCompleteness()throws Exception{
        try(var f=new SpiAuditFixture()){
            f.handlers.put(FAILURE,c->Reply.empty(503));
            var event=EventDeliverySpiAuditTests.event(org.keycloak.events.EventType.LOGIN_ERROR);
            assertDoesNotThrow(()->f.listener().onEvent(event));
            assertEquals(1,f.at(FAILURE).size()); // No automatic retry on 5xx and no durable queue.
            assertEquals(0,f.successes.get());assertEquals(0,f.denials.get());
            // Recovery does not replay a lost event by itself: PR-017 deliberately remains OPEN.
            f.handlers.put(FAILURE,c->Reply.empty(204));
            assertEquals(1,f.at(FAILURE).size());
        }
    }
}
