package com.zerotrust.keycloak.risk.strict;
import jakarta.ws.rs.container.*;
import jakarta.ws.rs.ext.Provider;
import jakarta.ws.rs.core.Response;
import java.util.*;
/** Bulk import/deletion has no per-subject pre-commit contract. Require controlled maintenance instead. */
@Provider @PreMatching
public final class UnsupportedBulkMutationFilter implements ContainerRequestFilter {
    @Override public void filter(ContainerRequestContext request) {
        var path=request.getUriInfo().getPathSegments().stream().map(s->s.getPath()).toList();
        String realm=Optional.ofNullable(System.getenv("ZT_SECURITY_REALM")).orElse("DoAn");
        if(path.size()<3 || !path.get(0).equals("admin") || !path.get(1).equals("realms") || !path.get(2).equals(realm))return;
        boolean deletion=request.getMethod().equals("DELETE") && path.size()==3;
        boolean bulk=request.getMethod().equals("POST") && path.size()==4 && Set.of("partialImport","partial-import").contains(path.get(3));
        if(deletion || bulk)request.abortWith(Response.status(403).type("application/json").entity(Map.of("error","D10_CONTROLLED_MAINTENANCE_REQUIRED")).build());
    }
}
