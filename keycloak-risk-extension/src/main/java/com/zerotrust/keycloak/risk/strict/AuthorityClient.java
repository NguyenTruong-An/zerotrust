package com.zerotrust.keycloak.risk.strict;

import com.zerotrust.keycloak.risk.client.*;
import com.zerotrust.keycloak.risk.config.*;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Map;

/** Service credentials stay in memory. Never caches an authorization or issuance result. */
public class AuthorityClient {
    private static final ServiceTokenCache TOKENS=new ServiceTokenCache();
    private static final java.util.concurrent.Semaphore TOKEN_LOAD=new java.util.concurrent.Semaphore(1);
    private final org.apache.http.impl.client.CloseableHttpClient http;
    private final ServiceTokenProvider tokens;
    private final URI base;
    public AuthorityClient(KeycloakSession session) {
        try {
            base=https(System.getenv("ZT_SECURITY_AUTHORITY"));
            URI token=https(System.getenv("ZT_SECURITY_TOKEN_ENDPOINT"));
            String secret=Files.readString(Path.of(System.getenv("ZT_SECURITY_SECRET_FILE"))).strip();
            var provider=session.getProvider(HttpClientProvider.class);
            http=provider.getHttpClient();
            tokens=new ClientCredentialsTokenProvider(provider,
                    new ServiceTokenConfig(token,"zerotrust-issuer-security",secret,java.time.Duration.ofSeconds(30)),
                    RiskScoringClientConfig.defaults(base),TOKENS);
        } catch(RuntimeException | java.io.IOException failure) { throw unavailable(); }
    }
    protected AuthorityClient() { base=null;http=null;tokens=null; }
    private URI https(String value) {
        URI uri=URI.create(value);
        if(!"https".equals(uri.getScheme()) || uri.getHost()==null || uri.getUserInfo()!=null || uri.getQuery()!=null || uri.getFragment()!=null) throw unavailable();
        return uri;
    }
    @SuppressWarnings("unchecked")
    public Map<String,Object> call(String path,Object body) {
        try {
            HttpPost request=new HttpPost(base.resolve("/internal/v1/security/"+path));
            request.setConfig(RequestConfig.custom().setConnectTimeout(1000).setConnectionRequestTimeout(500).setSocketTimeout(3000).setRedirectsEnabled(false).build());
            String machineToken=machineToken();
            request.setHeader("Authorization","Bearer "+machineToken);
            request.setHeader("Accept","application/json");
            request.setEntity(new StringEntity(JsonSerialization.writeValueAsString(body),ContentType.APPLICATION_JSON));
            try(var response=http.execute(request)) {
                int status=response.getStatusLine().getStatusCode();
                if(status==409) throw rejected();
                if(status==401){if(TOKEN_LOAD.tryAcquire(100,java.util.concurrent.TimeUnit.MILLISECONDS)){try{tokens.invalidate(machineToken);}finally{TOKEN_LOAD.release();}}throw unavailable();}
                if(status<200 || status>=300) throw unavailable();
                if(status==204) return Map.of();
                if(response.getEntity()==null) throw unavailable();
                try(var input=response.getEntity().getContent()) {
                    byte[] data=input.readNBytes(65537);
                    if(data.length>65536) throw unavailable();
                    return JsonSerialization.readValue(data,Map.class);
                }
            }
        } catch(WebApplicationException failure) { throw failure; }
        catch(Exception failure) { throw unavailable(); }
    }
    private String machineToken() throws InterruptedException {
        if(!TOKEN_LOAD.tryAcquire(100,java.util.concurrent.TimeUnit.MILLISECONDS))throw unavailable();
        try{return tokens.accessToken();}finally{TOKEN_LOAD.release();}
    }
    public static WebApplicationException rejected() { return error(401,"SECURITY_STATE_REJECTED"); }
    public static WebApplicationException unavailable() { return error(503,"SECURITY_AUTHORITY_UNAVAILABLE"); }
    private static WebApplicationException error(int status,String code) {
        return new WebApplicationException(Response.status(status).type("application/json").header("Cache-Control","no-store").entity(Map.of("error",code)).build());
    }
}
