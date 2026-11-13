package com.zerotrust.risk.securitystate;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;

@RestController
@RequestMapping("/internal/v1/security")
public class SecurityAuthorityController {
    private final SecurityAuthority authority;
    public SecurityAuthorityController(SecurityAuthority authority) { this.authority=authority; }
    public record Authentication(String subjectId,String clientId,String attemptId) {}
    public record Revoke(String subjectId,UUID operationId,String actorId,String kind,boolean quarantine,Boolean disabled) {}
    public record Challenge(SecurityAuthority.Context actor,String targetId,String action) {}
    public record Publish(String proofId,String actorId,String clientId,String attemptId,String method,long factorAt) {}
    @PostMapping("/authorizations") public ResponseEntity<Void> authorize(@RequestBody SecurityAuthority.Context request) {
        authority.authorize(request); return ResponseEntity.noContent().build();
    }
    @PostMapping("/authentications") public SecurityAuthority.Ticket authentication(@RequestBody Authentication request) {
        return authority.beginAuthentication(request.subjectId(),request.clientId(),request.attemptId());
    }
    @PostMapping("/sso-authorizations") public ResponseEntity<Void> sso(@RequestBody SecurityAuthority.Context request) {authority.sso(request);return ResponseEntity.noContent().build();}
    @PostMapping("/issuance") public SecurityAuthority.Issued issue(@RequestBody SecurityAuthority.Issuance request) { return authority.issue(request); }
    @PostMapping("/revocations") public SecurityAuthority.Operation revoke(@RequestBody Revoke request) {
        return authority.revoke(request.subjectId(),request.operationId(),request.actorId(),request.kind(),request.quarantine(),request.disabled());
    }
    @PostMapping("/challenges") public java.util.Map<String,String> challenge(@RequestBody Challenge request) { return java.util.Map.of("proofId",authority.challenge(request.actor(),request.targetId(),request.action())); }
    @PostMapping("/proofs") public SecurityAuthority.Proof publish(@RequestBody Publish request) {
        return authority.publish(request.proofId(),request.actorId(),request.clientId(),request.attemptId(),request.method(),request.factorAt());
    }
    @PostMapping("/resets") public SecurityAuthority.Operation reset(@RequestBody SecurityAuthority.BeginReset request) { return authority.beginReset(request); }
    public record OperationId(UUID operationId) {}
    public record NativeSession(String subjectId,String sessionId) {}
    @PostMapping("/native-session-revocations") public ResponseEntity<Void> session(@RequestBody NativeSession request) {authority.nativeSessionRevoke(request.subjectId(),request.sessionId());return ResponseEntity.noContent().build();}
    @PostMapping("/reset-work") public java.util.Map<String,Object> work() {return java.util.Map.of("operations",authority.pendingResets(),"externalOperations",authority.pendingExternal());}
    @PostMapping("/reset-next") public Object next(@RequestBody OperationId request) {var effect=authority.next(request.operationId());return effect==null?java.util.Map.of("completed",true):effect;}
    @PostMapping("/native-admission") public ResponseEntity<Void> admit(@RequestBody SecurityAuthority.Effect request) {authority.admit(request);return ResponseEntity.noContent().build();}
    @PostMapping("/native-confirmation") public ResponseEntity<Void> confirmed(@RequestBody SecurityAuthority.Effect request) {authority.confirmed(request);return ResponseEntity.noContent().build();}
    @PostMapping("/external-confirmation") public ResponseEntity<Void> external(@RequestBody OperationId request) {authority.externalConfirmed(request.operationId());return ResponseEntity.noContent().build();}
    @ExceptionHandler({org.springframework.dao.DataAccessException.class, org.springframework.transaction.TransactionException.class})
    public ResponseEntity<java.util.Map<String,String>> unavailable() {
        return ResponseEntity.status(503).body(java.util.Map.of("error","AUTHORITY_UNAVAILABLE"));
    }
}
