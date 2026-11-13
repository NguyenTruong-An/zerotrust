package com.zerotrust.zerotrust.security;
import org.springframework.scheduling.annotation.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import com.zerotrust.zerotrust.exception.*;
import java.util.*;
@Service
public final class StrictResetOrchestrator {
    private final StrictSecurityAuthorityClient authority;
    private final FreshAdminMfaGuard guard;
    public StrictResetOrchestrator(StrictSecurityAuthorityClient authority,FreshAdminMfaGuard guard){this.authority=authority;this.guard=guard;}
    public Map<String,Object> challenge(Authentication authentication,String target) {
        if(!(authentication instanceof JwtAuthenticationToken token) || authentication.getAuthorities().stream().noneMatch(a->a.getAuthority().equals("ROLE_ADMIN")))throw new WebException(ErrorCode.FORBIDDEN);
        try {
            var response=authority.post("challenges",Map.of("actor",authority.context(token.getToken()),"targetId",target,"action","MFA_RESET"));
            return Map.of("proofId",response.get("proofId"),"targetId",target);
        }catch(StrictSecurityAuthorityClient.Rejected e){throw new WebException(ErrorCode.FRESH_ADMIN_MFA_REQUIRED);}
        catch(StrictSecurityAuthorityClient.Unavailable e){throw new WebException(ErrorCode.MFA_RESET_PARTIAL);}
    }
    public void reset(Authentication authentication,String target) {
        String proof=guard.requireReset(authentication,target);
        try {
            var actor=authority.context(((JwtAuthenticationToken)authentication).getToken());
            var operation=authority.post("resets",Map.of("actor",actor,"targetId",target,"proofId",proof,"operationId",UUID.randomUUID().toString()));
            resume((String)operation.get("operationId"));
        }catch(StrictSecurityAuthorityClient.Rejected e){throw new WebException(ErrorCode.FRESH_ADMIN_MFA_REQUIRED);}
        catch(StrictSecurityAuthorityClient.Unavailable e){throw new WebException(ErrorCode.MFA_RESET_PARTIAL);}
    }
    public void resume(String operation) {
        for(int step=0;step<4;step++) {
            var effect=authority.post("reset-next",Map.of("operationId",operation));
            if(Boolean.TRUE.equals(effect.get("completed")))return;
            authority.nativeEffect(effect);
        }
        throw new StrictSecurityAuthorityClient.Unavailable();
    }
    @Scheduled(fixedDelay=5000)
    public void recover() {
        try {
            var pending=authority.post("reset-work",Map.of());
            var work=pending.get("operations");
            if(work instanceof List<?> operations)for(Object operation:operations) {
                try{resume((String)operation);}catch(RuntimeException ignored){/* pending retained; native fencing owns every retry */}
            }
            if(pending.get("externalOperations") instanceof List<?> external)for(Object value:external) {
                if(value instanceof Map<?,?> row)try{authority.nativeEffect(Map.of("operationId",row.get("operationId"),"subjectId",row.get("subjectId"),"epoch",row.get("epoch"),"effectId",row.get("operationId"),"action","EXTERNAL_RECONCILE"));}catch(RuntimeException ignored){/* only positive committed receipts release quarantine */}
            }
        }catch(RuntimeException ignored){/* authority outage never clears pending */}
    }
}
