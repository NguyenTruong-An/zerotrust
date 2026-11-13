package com.zerotrust.keycloak.risk.strict;
import org.junit.jupiter.api.Test;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.*;
import java.util.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;
class UnsupportedBulkMutationFilterTest {
    ContainerRequestContext request(String method,String path){var request=mock(ContainerRequestContext.class);var uri=mock(UriInfo.class);when(request.getUriInfo()).thenReturn(uri);when(request.getMethod()).thenReturn(method);when(uri.getPathSegments()).thenReturn(Arrays.stream(path.split("/")).map(value->(PathSegment)new PathSegment(){public String getPath(){return value;}public MultivaluedMap<String,String> getMatrixParameters(){return new MultivaluedHashMap<>();}}).toList());return request;}
    @Test void unsupportedBulkImportAndRealmDeletionAreRejectedBeforeMutation(){for(String path:List.of("partialImport","partial-import")){var request=request("POST","admin/realms/DoAn/"+path);new UnsupportedBulkMutationFilter().filter(request);verify(request).abortWith(argThat(r->r.getStatus()==403));}var deletion=request("DELETE","admin/realms/DoAn");new UnsupportedBulkMutationFilter().filter(deletion);verify(deletion).abortWith(argThat(r->r.getStatus()==403));}
    @Test void ordinarySubjectMutationAndReadStillReachNativeAuthorization(){for(var entry:List.of(Map.entry("PUT","admin/realms/DoAn/users/u/reset-password"),Map.entry("GET","admin/realms/DoAn"),Map.entry("DELETE","admin/realms/Other"))){var request=request(entry.getKey(),entry.getValue());new UnsupportedBulkMutationFilter().filter(request);verify(request,never()).abortWith(any());}}
}
