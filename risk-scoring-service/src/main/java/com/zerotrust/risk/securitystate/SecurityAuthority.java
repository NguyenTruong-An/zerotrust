package com.zerotrust.risk.securitystate;

import com.zerotrust.risk.domain.SubjectIdentifierNormalizer;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.*;
import java.util.*;

/** Primary-DB linearization points. No cached positive result and no replica datasource. */
@Service
@Transactional(isolation=Isolation.READ_COMMITTED, timeout=5)
public class SecurityAuthority {
    private final JdbcTemplate jdbc;
    private final Clock clock;
    private final com.zerotrust.risk.service.DeviceTrustLifecycle trust;
    public SecurityAuthority(JdbcTemplate jdbc, Clock clock,com.zerotrust.risk.service.DeviceTrustLifecycle trust) { this.jdbc=jdbc; this.clock=clock; this.trust=trust; }

    public record Context(String subjectId,String sessionId,String clientId,long epoch) {}
    public record Ticket(String ticket,long epoch) {}
    public record Issuance(Context context,String ticket,String proofId,String codeId) {}
    public record Proof(String proofId,String actorId,String targetId,String action,String clientId,
                        String attemptId,String method,long factorAt) {}
    public record BeginReset(Context actor,String targetId,String proofId,UUID operationId) {}
    public record Operation(UUID operationId,String subjectId,String actorId,long epoch,String stage,long version) {}
    public record Effect(UUID operationId,String subjectId,long epoch,String effectId,String action) {}
    private record Subject(long epoch,boolean disabled,String pending) {}

    private Instant now() { return clock.instant(); }
    private Timestamp ts(Instant i) { return Timestamp.from(i); }
    private String subject(String value) { return SubjectIdentifierNormalizer.normalize(value); }
    private String text(String value) {
        if(value==null || value.isBlank() || value.length()>255 || value.chars().anyMatch(Character::isISOControl)) throw new SecurityStateRejected();
        return value;
    }
    private String hash(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text(value).getBytes(StandardCharsets.UTF_8))); }
        catch(java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
    private Subject lock(String id,boolean create) {
        id=subject(id);
        if(create) jdbc.update("INSERT INTO security_subjects(subject_id,security_epoch,account_disabled,updated_at) VALUES(?,1,FALSE,?) ON DUPLICATE KEY UPDATE subject_id=subject_id",id,ts(now()));
        else jdbc.update("UPDATE security_subjects SET subject_id=subject_id WHERE subject_id=?",id);
        // The no-op write requires a writer connection. A read-only/delayed replica cannot authorize.
        var rows=jdbc.query("SELECT security_epoch,account_disabled,pending_operation_id FROM security_subjects WHERE subject_id=? FOR UPDATE",
                (r,n)->new Subject(r.getLong(1),r.getBoolean(2),r.getString(3)),id);
        if(rows.size()!=1) throw new SecurityStateRejected();
        return rows.get(0);
    }
    private void active(Subject row) { if(row.disabled || row.pending!=null) throw new SecurityStateRejected(); }

    public void authorize(Context ctx) {
        Objects.requireNonNull(ctx); String id=subject(ctx.subjectId());
        Subject row=lock(id,false); active(row);
        if(ctx.epoch()<1 || row.epoch!=ctx.epoch()) throw new SecurityStateRejected();
        var matches=jdbc.queryForObject("SELECT COUNT(*) FROM security_sessions s JOIN security_session_clients c ON c.session_id=s.session_id AND c.security_epoch=s.security_epoch WHERE s.session_id=? AND s.subject_id=? AND c.client_id=? AND s.security_epoch=? AND s.revoked=FALSE",
                Integer.class,text(ctx.sessionId()),id,text(ctx.clientId()),ctx.epoch());
        if(matches==null || matches!=1) throw new SecurityStateRejected();
    }
    /** Issuer-only: native cookie verification already proved this exact SID and subject. */
    public void sso(Context ctx) {
        Subject row=lock(subject(ctx.subjectId()),false);active(row);
        if(row.epoch!=ctx.epoch())throw new SecurityStateRejected();
        requireSession(ctx,row.epoch);
        bindClient(ctx);
    }
    private void requireSession(Context ctx,long epoch) {
        var rows=jdbc.queryForList("SELECT subject_id,security_epoch FROM security_sessions WHERE session_id=? AND revoked=FALSE FOR UPDATE",text(ctx.sessionId()));
        if(rows.size()!=1)throw new SecurityStateRejected();var session=rows.get(0);
        if(!ctx.subjectId().equals(session.get("subject_id")) || epoch!=((Number)session.get("security_epoch")).longValue())throw new SecurityStateRejected();
    }
    private void bindClient(Context ctx) {
        jdbc.update("INSERT INTO security_session_clients(session_id,client_id,security_epoch) VALUES(?,?,?) ON DUPLICATE KEY UPDATE session_id=session_id",text(ctx.sessionId()),text(ctx.clientId()),ctx.epoch());
        authorize(ctx);
    }

    public Ticket beginAuthentication(String subjectId,String clientId,String attemptId) {
        String id=subject(subjectId); Subject row=lock(id,true); active(row);
        if(trust.snapshot(id).resetPending()) throw new SecurityStateRejected();
        String ticket=UUID.randomUUID().toString()+UUID.randomUUID();
        jdbc.update("INSERT INTO security_authentication_tickets(ticket_hash,subject_id,client_id,attempt_id,security_epoch,expires_at) VALUES(?,?,?,?,?,?)",
                hash(ticket),id,text(clientId),text(attemptId),row.epoch,ts(now().plusSeconds(600)));
        return new Ticket(ticket,row.epoch);
    }

    public record Issued(long epoch,Proof proof) {}
    public Issued issue(Issuance request) {
        Context ctx=request.context(); String id=subject(ctx.subjectId()); Subject row=lock(id,false); active(row);
        if(ctx.epoch()!=row.epoch || ctx.epoch()<1)throw new SecurityStateRejected();
        if(request.ticket()==null) { authorize(ctx); return new Issued(ctx.epoch(),null); }
        var tickets=jdbc.queryForList("SELECT subject_id,client_id,attempt_id,security_epoch,bound_session_id,expires_at FROM security_authentication_tickets WHERE ticket_hash=? FOR UPDATE",hash(request.ticket()));
        if(tickets.size()!=1) throw new SecurityStateRejected();
        var t=tickets.get(0);
        if(!id.equals(t.get("subject_id")) || !text(ctx.clientId()).equals(t.get("client_id"))
                || ((Number)t.get("security_epoch")).longValue()!=row.epoch
                || !((Timestamp)t.get("expires_at")).toInstant().isAfter(now())
                || t.get("bound_session_id")!=null && !ctx.sessionId().equals(t.get("bound_session_id"))) throw new SecurityStateRejected();
        var existing=jdbc.queryForList("SELECT subject_id,client_id,security_epoch,revoked FROM security_sessions WHERE session_id=? FOR UPDATE",text(ctx.sessionId()));
        if(existing.isEmpty()) {
            jdbc.update("INSERT INTO security_sessions(session_id,subject_id,client_id,security_epoch,created_at) VALUES(?,?,?,?,?)",ctx.sessionId(),id,ctx.clientId(),row.epoch,ts(now()));
        } else {
            requireSession(ctx,row.epoch);
        }
        bindClient(ctx);
        jdbc.update("UPDATE security_authentication_tickets SET bound_session_id=? WHERE ticket_hash=?",ctx.sessionId(),hash(request.ticket()));
        Proof delivered=null;
        if(request.proofId()!=null) {
            var proofs=jdbc.queryForList("SELECT * FROM security_action_proofs WHERE proof_id=? FOR UPDATE",text(request.proofId()));
            if(proofs.size()!=1) throw new SecurityStateRejected(); var p=proofs.get(0);
            if(!id.equals(p.get("actor_id")) || !ctx.clientId().equals(p.get("client_id"))
                    || ((Number)p.get("actor_epoch")).longValue()!=row.epoch
                    || !t.get("attempt_id").equals(p.get("attempt_id"))
                    || !((Timestamp)p.get("expires_at")).toInstant().isAfter(now())
                    || !((Timestamp)p.get("factor_at")).toInstant().plusSeconds(300).isAfter(now())) throw new SecurityStateRejected();
            String code=text(request.codeId());
            if("PUBLISHED".equals(p.get("state"))) {
                jdbc.update("UPDATE security_action_proofs SET state='DELIVERED',proof_session_id=?,delivery_code_id=? WHERE proof_id=?",ctx.sessionId(),code,request.proofId());
            } else if(!"DELIVERED".equals(p.get("state")) || !ctx.sessionId().equals(p.get("proof_session_id")) || !code.equals(p.get("delivery_code_id"))) {
                throw new SecurityStateRejected();
            }
            delivered=new Proof(request.proofId(),id,(String)p.get("target_id"),(String)p.get("action_name"),ctx.clientId(),(String)p.get("attempt_id"),(String)p.get("factor_method"),((Timestamp)p.get("factor_at")).toInstant().getEpochSecond());
        }
        return new Issued(row.epoch,delivered);
    }

    public Operation revoke(String subjectId,UUID operationId,String actorId,String kind,boolean quarantine,Boolean disabled) {
        String id=subject(subjectId); text(actorId); text(kind); Subject row=lock(id,true);
        var old=jdbc.queryForList("SELECT subject_id,actor_id,operation_kind,security_epoch,stage,stage_version FROM security_operations WHERE operation_id=?",operationId.toString());
        if(!old.isEmpty()) {
            var o=old.get(0);
            if(!id.equals(o.get("subject_id")) || !actorId.equals(o.get("actor_id")) || !kind.equals(o.get("operation_kind"))) throw new SecurityStateRejected();
            return new Operation(operationId,id,actorId,((Number)o.get("security_epoch")).longValue(),(String)o.get("stage"),((Number)o.get("stage_version")).longValue());
        }
        // An unresolved native operation cannot be superseded by another mutation.
        if(row.pending!=null) throw new SecurityStateRejected();
        if(trust.snapshot(id).resetPending())throw new SecurityStateRejected(); // do not supersede unresolved V7 operations
        long next=Math.addExact(row.epoch,1);
        jdbc.update("UPDATE security_subjects SET security_epoch=?,account_disabled=?,pending_operation_id=?,updated_at=? WHERE subject_id=?",
                next,disabled==null?row.disabled:disabled,quarantine?operationId.toString():null,ts(now()),id);
        jdbc.update("UPDATE security_sessions SET revoked=TRUE,revoked_at=? WHERE subject_id=? AND revoked=FALSE",ts(now()),id);
        String stage=quarantine?"REVOKED":"COMPLETED";
        jdbc.update("INSERT INTO security_operations(operation_id,subject_id,actor_id,operation_kind,security_epoch,stage,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                operationId.toString(),id,actorId,kind,next,stage,ts(now()),ts(now()));
        trust.revoke(id,operationId,actorId);
        if(!quarantine) trust.complete(id,operationId,actorId);
        return new Operation(operationId,id,actorId,next,stage,0);
    }

    public String challenge(Context actor,String targetId,String action) {
        authorize(actor); subject(targetId);
        if(!"MFA_RESET".equals(action)) throw new SecurityStateRejected();
        String nonce=UUID.randomUUID().toString();
        jdbc.update("INSERT INTO security_action_proofs(proof_id,actor_id,actor_session_id,actor_epoch,client_id,target_id,action_name,state,expires_at) VALUES(?,?,?,?,?,?,?,'CREATED',?)",
                nonce,actor.subjectId(),actor.sessionId(),actor.epoch(),actor.clientId(),targetId,action,ts(now().plusSeconds(600)));
        return nonce;
    }

    public Proof publish(String proofId,String actorId,String clientId,String attemptId,String method,long factorAt) {
        String actor=subject(actorId); Subject actorState=lock(actor,false); active(actorState);
        var rows=jdbc.queryForList("SELECT * FROM security_action_proofs WHERE proof_id=? FOR UPDATE",text(proofId));
        if(rows.size()!=1) throw new SecurityStateRejected(); var p=rows.get(0);
        Instant at=Instant.ofEpochSecond(factorAt);
        if(!actor.equals(p.get("actor_id")) || !clientId.equals(p.get("client_id")) || ((Number)p.get("actor_epoch")).longValue()!=actorState.epoch
                || !Set.of("otp","recovery-authn-codes").contains(method)
                || at.isAfter(now()) || at.isBefore(now().minusSeconds(300))
                || !((Timestamp)p.get("expires_at")).toInstant().isAfter(now())) throw new SecurityStateRejected();
        if(!"CREATED".equals(p.get("state"))) {
            if(!"PUBLISHED".equals(p.get("state")) || !attemptId.equals(p.get("attempt_id")) || !method.equals(p.get("factor_method"))) throw new SecurityStateRejected();
            at=((Timestamp)p.get("factor_at")).toInstant();
        } else {
            jdbc.update("UPDATE security_action_proofs SET state='PUBLISHED',attempt_id=?,factor_method=?,factor_at=? WHERE proof_id=?",text(attemptId),method,ts(at),proofId);
        }
        return new Proof(proofId,actor,(String)p.get("target_id"),(String)p.get("action_name"),clientId,attemptId,method,at.getEpochSecond());
    }

    public Operation beginReset(BeginReset request) {
        Context actor=request.actor();
        // Stable lock order for self reset and two admins resetting one another.
        var ids=new TreeSet<>(List.of(subject(actor.subjectId()),subject(request.targetId())));
        for(String id:ids) lock(id,id.equals(request.targetId()));
        authorize(actor);
        var previous=jdbc.queryForList("SELECT actor_id,subject_id FROM security_operations WHERE operation_id=?",request.operationId().toString());
        if(!previous.isEmpty()) {
            var o=previous.get(0);
            if(!actor.subjectId().equals(o.get("actor_id")) || !request.targetId().equals(o.get("subject_id"))) throw new SecurityStateRejected();
            return operation(request.operationId(),actor.subjectId());
        }
        var proofs=jdbc.queryForList("SELECT * FROM security_action_proofs WHERE proof_id=? FOR UPDATE",request.proofId());
        if(proofs.size()!=1) throw new SecurityStateRejected(); var p=proofs.get(0);
        if(!actor.subjectId().equals(p.get("actor_id")) || !actor.clientId().equals(p.get("client_id"))
                || !actor.sessionId().equals(p.get("proof_session_id")) || ((Number)p.get("actor_epoch")).longValue()!=actor.epoch()
                || !request.targetId().equals(p.get("target_id")) || !"MFA_RESET".equals(p.get("action_name")))throw new SecurityStateRejected();
        if("CONSUMED".equals(p.get("state")) && actor.subjectId().equals(p.get("actor_id")) && request.targetId().equals(p.get("target_id")))
            return operation(UUID.fromString((String)p.get("consumed_operation_id")),actor.subjectId());
        if(!"DELIVERED".equals(p.get("state")) || !actor.sessionId().equals(p.get("proof_session_id")) || !actor.subjectId().equals(p.get("actor_id"))
                || !actor.clientId().equals(p.get("client_id")) || !request.targetId().equals(p.get("target_id"))
                || !"MFA_RESET".equals(p.get("action_name")) || ((Number)p.get("actor_epoch")).longValue()!=actor.epoch()
                || !((Timestamp)p.get("factor_at")).toInstant().plusSeconds(300).isAfter(now())
                || !((Timestamp)p.get("expires_at")).toInstant().isAfter(now())) throw new SecurityStateRejected();
        jdbc.update("UPDATE security_action_proofs SET state='CONSUMED',consumed_operation_id=? WHERE proof_id=?",request.operationId().toString(),request.proofId());
        return revoke(request.targetId(),request.operationId(),actor.subjectId(),"MFA_RESET",true,null);
    }

    public Operation operation(UUID id,String actor) {
        var rows=jdbc.query("SELECT subject_id,actor_id,security_epoch,stage,stage_version FROM security_operations WHERE operation_id=? FOR UPDATE",
                (r,n)->new Operation(id,r.getString(1),r.getString(2),r.getLong(3),r.getString(4),r.getLong(5)),id.toString());
        if(rows.size()!=1 || !actor.equals(rows.get(0).actorId())) throw new SecurityStateRejected(); return rows.get(0);
    }

    private Map<String,Object> lockedOperation(UUID id) {
        var subject=jdbc.queryForList("SELECT subject_id FROM security_operations WHERE operation_id=?",id.toString());
        if(subject.size()!=1) throw new SecurityStateRejected();
        String target=(String)subject.get(0).get("subject_id"); Subject state=lock(target,false);
        var row=jdbc.queryForMap("SELECT * FROM security_operations WHERE operation_id=? FOR UPDATE",id.toString());
        if(!"COMPLETED".equals(row.get("stage")) && (!id.toString().equals(state.pending) || state.epoch!=((Number)row.get("security_epoch")).longValue())) throw new SecurityStateRejected();
        return row;
    }
    private void stage(UUID id,String stage) {
        jdbc.update("UPDATE security_operations SET stage=?,stage_version=stage_version+1,updated_at=? WHERE operation_id=?",stage,ts(now()),id.toString());
    }
    /** Called only by the dedicated worker. A crash returns the same durable effect identity. */
    public Effect next(UUID id) {
        var o=lockedOperation(id);
        if(!"MFA_RESET".equals(o.get("operation_kind"))) throw new SecurityStateRejected();
        String current=(String)o.get("stage");
        if("COMPLETED".equals(current)) return null;
        if("FINAL_LOGOUT_DONE".equals(current)) {finish(id,o);return null;}
        String action=switch(current) {
            case "REVOKED"->"EARLY_LOGOUT";
            case "EARLY_LOGOUT_DONE"->"CREDENTIAL_MUTATION";
            case "CREDENTIAL_MUTATION_DONE"->"FINAL_LOGOUT";
            default->null;
        };
        String effect=(String)o.get("effect_id");
        if(action!=null) {
            effect=UUID.randomUUID().toString();
            jdbc.update("UPDATE security_operations SET effect_id=?,effect_action=? WHERE operation_id=?",effect,action,id.toString());
            stage(id,action+"_DISPATCHED");
        } else {
            action=(String)o.get("effect_action");
            if(action==null || !Set.of(action+"_DISPATCHED",action+"_ACCEPTED").contains(current)) throw new SecurityStateRejected();
        }
        return new Effect(id,(String)o.get("subject_id"),((Number)o.get("security_epoch")).longValue(),effect,action);
    }
    private Map<String,Object> matching(Effect effect) {
        var o=lockedOperation(effect.operationId());
        if(!effect.subjectId().equals(o.get("subject_id")) || effect.epoch()!=((Number)o.get("security_epoch")).longValue()
                || !effect.effectId().equals(o.get("effect_id")) || !effect.action().equals(o.get("effect_action"))) throw new SecurityStateRejected();
        return o;
    }
    /** Native caller holds its subject DB row lock from BEFORE admission through native commit. */
    public void admit(Effect effect) {
        var o=matching(effect);String stage=(String)o.get("stage");
        if((effect.action()+"_DISPATCHED").equals(stage)) stage(effect.operationId(),effect.action()+"_ACCEPTED");
        else if(!(effect.action()+"_ACCEPTED").equals(stage)) throw new SecurityStateRejected();
    }
    /** Invoked after native commit, or after reading the matching committed native receipt. */
    public void confirmed(Effect effect) {
        var o=matching(effect);String stage=(String)o.get("stage");
        if((effect.action()+"_DONE").equals(stage) || "COMPLETED".equals(stage))return;
        if(!(effect.action()+"_ACCEPTED").equals(stage)) throw new SecurityStateRejected();
        stage(effect.operationId(),effect.action()+"_DONE");
    }
    private void finish(UUID id,Map<String,Object> o) {
        String target=(String)o.get("subject_id"),actor=(String)o.get("actor_id");
        trust.complete(target,id,actor);
        jdbc.update("UPDATE security_subjects SET pending_operation_id=NULL,updated_at=? WHERE subject_id=? AND pending_operation_id=?",ts(now()),target,id.toString());
        stage(id,"COMPLETED");
    }
    public void externalConfirmed(UUID id) {
        var o=lockedOperation(id);
        if(!"EXTERNAL_MUTATION".equals(o.get("operation_kind")))throw new SecurityStateRejected();
        if("COMPLETED".equals(o.get("stage")))return;
        if(!"REVOKED".equals(o.get("stage")))throw new SecurityStateRejected();
        finish(id,o);
    }
    public List<UUID> pendingResets() {
        return jdbc.query("SELECT operation_id FROM security_operations WHERE operation_kind='MFA_RESET' AND stage<>'COMPLETED' ORDER BY created_at LIMIT 20",(r,n)->UUID.fromString(r.getString(1)));
    }
    public List<Map<String,Object>> pendingExternal() {
        return jdbc.query("SELECT operation_id,subject_id,security_epoch FROM security_operations WHERE operation_kind='EXTERNAL_MUTATION' AND stage<>'COMPLETED' ORDER BY created_at LIMIT 20",(r,n)->Map.of("operationId",r.getString(1),"subjectId",r.getString(2),"epoch",r.getLong(3)));
    }
    public void deviceCompletion(String subject,UUID id,String actor) {
        var o=lockedOperation(id);
        if(!subject.equals(o.get("subject_id")) || !actor.equals(o.get("actor_id")) || !"DEVICE_REVOKE".equals(o.get("operation_kind")) || !"COMPLETED".equals(o.get("stage")))throw new SecurityStateRejected();
    }
    public void nativeSessionRevoke(String subjectId,String sessionId) {
        String id=subject(subjectId);lock(id,false);
        var rows=jdbc.queryForList("SELECT subject_id FROM security_sessions WHERE session_id=? FOR UPDATE",text(sessionId));
        if(rows.size()!=1 || !id.equals(rows.get(0).get("subject_id")))throw new SecurityStateRejected();
        jdbc.update("UPDATE security_sessions SET revoked=TRUE,revoked_at=? WHERE session_id=? AND revoked=FALSE",ts(now()),sessionId);
    }
}
