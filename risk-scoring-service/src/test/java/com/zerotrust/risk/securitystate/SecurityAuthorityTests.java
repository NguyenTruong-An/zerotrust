package com.zerotrust.risk.securitystate;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.jdbc.core.JdbcTemplate;
import java.util.*;
import java.util.concurrent.*;
import static org.assertj.core.api.Assertions.*;

@SpringBootTest @ActiveProfiles("test")
class SecurityAuthorityTests {
    @Autowired SecurityAuthority authority;
    @Autowired JdbcTemplate jdbc;
    private SecurityAuthority.Context session(String subject) {
        String sid=UUID.randomUUID().toString();
        var t=authority.beginAuthentication(subject,"zerotrust-spa",UUID.randomUUID().toString());
        var ctx=new SecurityAuthority.Context(subject,sid,"zerotrust-spa",t.epoch());
        authority.issue(new SecurityAuthority.Issuance(ctx,t.ticket(),null,null));
        return ctx;
    }
    private String id() { return UUID.randomUUID().toString(); }
    @Test void revokeIsDurableAcrossNewCallsAndAllSessionsButOtherSubjectSurvives() {
        String subject=id(); var a=session(subject); var b=session(subject); var other=session(id());
        authority.authorize(a); authority.revoke(subject,UUID.randomUUID(),id(),"SUBJECT_REVOKE",false,null);
        assertThatThrownBy(()->authority.authorize(a)).isInstanceOf(SecurityStateRejected.class);
        assertThatThrownBy(()->authority.authorize(b)).isInstanceOf(SecurityStateRejected.class);
        assertThatCode(()->authority.authorize(other)).doesNotThrowAnyException();
    }
    @Test void sameSecondTicketCannotMintAfterRevocationAndOldSessionCannotUpgrade() {
        String s=id(); var current=session(s);
        var ticket=authority.beginAuthentication(s,"zerotrust-spa",id());
        authority.revoke(s,UUID.randomUUID(),id(),"REVOKE",false,null);
        assertThatThrownBy(()->authority.issue(new SecurityAuthority.Issuance(new SecurityAuthority.Context(s,id(),"zerotrust-spa",ticket.epoch()),ticket.ticket(),null,null))).isInstanceOf(SecurityStateRejected.class);
        var fresh=authority.beginAuthentication(s,"zerotrust-spa",id());
        assertThatThrownBy(()->authority.issue(new SecurityAuthority.Issuance(new SecurityAuthority.Context(s,current.sessionId(),"zerotrust-spa",fresh.epoch()),fresh.ticket(),null,null))).isInstanceOf(SecurityStateRejected.class);
    }
    @Test void resetPendingDeniesFreshAuthenticationAndExistingAuthorization() {
        String s=id(); var ctx=session(s);
        authority.revoke(s,UUID.randomUUID(),id(),"MFA_RESET",true,null);
        assertThatThrownBy(()->authority.beginAuthentication(s,"zerotrust-spa",id())).isInstanceOf(SecurityStateRejected.class);
        assertThatThrownBy(()->authority.authorize(ctx)).isInstanceOf(SecurityStateRejected.class);
    }
    @Test void revokeIdempotencyNeverDecreasesEpochOrRevivesTombstone() {
        String s=id(),actor=id(); var ctx=session(s); UUID op=UUID.randomUUID();
        var first=authority.revoke(s,op,actor,"REVOKE",false,null);
        var second=authority.revoke(s,UUID.randomUUID(),actor,"REVOKE",false,null);
        assertThat(authority.revoke(s,op,actor,"REVOKE",false,null)).isEqualTo(first);
        assertThat(second.epoch()).isEqualTo(first.epoch()+1);
        assertThatThrownBy(()->authority.authorize(ctx)).isInstanceOf(SecurityStateRejected.class);
        assertThatThrownBy(()->authority.revoke(s,op,id(),"REVOKE",false,null)).isInstanceOf(SecurityStateRejected.class);
    }
    @Test void concurrentRevokeAndAuthorizationCannotAllowAFreshCallAfterCommit() throws Exception {
        String s=id(); var ctx=session(s); ExecutorService pool=Executors.newFixedThreadPool(2);
        try {
            var revoke=pool.submit(()->authority.revoke(s,UUID.randomUUID(),id(),"REVOKE",false,null));
            revoke.get(10,TimeUnit.SECONDS);
            for(int i=0;i<20;i++) assertThatThrownBy(()->authority.authorize(ctx)).isInstanceOf(SecurityStateRejected.class);
        } finally { pool.shutdownNow(); }
    }
    @Test void nonceIsActorTargetClientBoundAndConsumedInSameTransactionAsRevoke() {
        var actor=session(id()); String target=id(); session(target);
        String proof=authority.challenge(actor,target,"MFA_RESET");
        String attempt=id();
        authority.publish(proof,actor.subjectId(),actor.clientId(),attempt,"otp",java.time.Instant.now().getEpochSecond());
        var ticket=authority.beginAuthentication(actor.subjectId(),actor.clientId(),attempt);
        authority.issue(new SecurityAuthority.Issuance(actor,ticket.ticket(),proof,id()));
        UUID operation=UUID.randomUUID();
        assertThatThrownBy(()->authority.beginReset(new SecurityAuthority.BeginReset(actor,id(),proof,operation))).isInstanceOf(SecurityStateRejected.class);
        var result=authority.beginReset(new SecurityAuthority.BeginReset(actor,target,proof,operation));
        assertThat(result.stage()).isEqualTo("REVOKED");
        assertThat(authority.beginReset(new SecurityAuthority.BeginReset(actor,target,proof,UUID.randomUUID())).operationId()).isEqualTo(operation);
        assertThat(jdbc.queryForObject("SELECT consumed_operation_id FROM security_action_proofs WHERE proof_id=?",String.class,proof)).isEqualTo(operation.toString());
    }
    @Test void missingLegacyEpochWrongClientAndUnknownSessionAreRejected() {
        var ctx=session(id());
        assertThatThrownBy(()->authority.authorize(new SecurityAuthority.Context(ctx.subjectId(),ctx.sessionId(),ctx.clientId(),0))).isInstanceOf(SecurityStateRejected.class);
        assertThatThrownBy(()->authority.authorize(new SecurityAuthority.Context(ctx.subjectId(),ctx.sessionId(),"other",ctx.epoch()))).isInstanceOf(SecurityStateRejected.class);
        assertThatThrownBy(()->authority.authorize(new SecurityAuthority.Context(ctx.subjectId(),id(),ctx.clientId(),ctx.epoch()))).isInstanceOf(SecurityStateRejected.class);
    }
    @Test void verifiedSsoBindsAnotherClientWithoutUpgradingRevokedSession() {
        var current=session(id());var other=new SecurityAuthority.Context(current.subjectId(),current.sessionId(),"account-console",current.epoch());
        assertThatThrownBy(()->authority.authorize(other)).isInstanceOf(SecurityStateRejected.class);
        authority.sso(other);authority.authorize(other);
        authority.nativeSessionRevoke(current.subjectId(),current.sessionId());
        assertThatThrownBy(()->authority.authorize(current)).isInstanceOf(SecurityStateRejected.class);
        assertThatThrownBy(()->authority.sso(other)).isInstanceOf(SecurityStateRejected.class);
    }
    @Test void verifiedSessionLogoutIsIdempotentAndCannotRevokeAnotherSubjectOrSession() {
        String subject=id();var one=session(subject);var two=session(subject);
        assertThatThrownBy(()->authority.nativeSessionRevoke(id(),one.sessionId())).isInstanceOf(SecurityStateRejected.class);
        authority.nativeSessionRevoke(subject,one.sessionId());authority.nativeSessionRevoke(subject,one.sessionId());
        authority.authorize(two);assertThatThrownBy(()->authority.authorize(one)).isInstanceOf(SecurityStateRejected.class);
    }
    @Test void unknownEffectResumesWithSameIdentityAndStagesCannotSkipOrRollBack() {
        String subject=id(),actor=id();session(subject);
        var op=authority.revoke(subject,UUID.randomUUID(),actor,"MFA_RESET",true,null);
        var first=authority.next(op.operationId());assertThat(first.action()).isEqualTo("EARLY_LOGOUT");
        assertThatThrownBy(()->authority.confirmed(first)).isInstanceOf(SecurityStateRejected.class);
        authority.admit(first);assertThat(authority.next(op.operationId())).isEqualTo(first);authority.admit(first);
        assertThatThrownBy(()->authority.revoke(subject,UUID.randomUUID(),actor,"MFA_RESET",true,null)).isInstanceOf(SecurityStateRejected.class);
        authority.confirmed(first);authority.confirmed(first);
        var mutation=authority.next(op.operationId());assertThat(mutation.action()).isEqualTo("CREDENTIAL_MUTATION");
        assertThatThrownBy(()->authority.admit(first)).isInstanceOf(SecurityStateRejected.class);
        authority.admit(mutation);authority.confirmed(mutation);
        var last=authority.next(op.operationId());assertThat(last.action()).isEqualTo("FINAL_LOGOUT");
        assertThatThrownBy(()->authority.beginAuthentication(subject,"zerotrust-spa",id())).isInstanceOf(SecurityStateRejected.class);
        authority.admit(last);authority.confirmed(last);assertThat(authority.next(op.operationId())).isNull();
        assertThat(authority.operation(op.operationId(),actor).stage()).isEqualTo("COMPLETED");
        var newer=authority.revoke(subject,UUID.randomUUID(),actor,"MFA_RESET",true,null);
        assertThat(newer.epoch()).isGreaterThan(op.epoch());authority.confirmed(last);
        assertThatThrownBy(()->authority.beginAuthentication(subject,"zerotrust-spa",id())).isInstanceOf(SecurityStateRejected.class);
    }
    @Test void unresolvedV7TrustOperationCannotBeSilentlySuperseded() {
        String subject=id();session(subject);
        UUID legacy=UUID.randomUUID();
        jdbc.update("UPDATE subject_device_trust SET pending_operation_id=? WHERE subject_id=?",legacy.toString(),subject);
        assertThatThrownBy(()->authority.revoke(subject,UUID.randomUUID(),id(),"REVOKE",false,null)).isInstanceOf(SecurityStateRejected.class);
    }
}
