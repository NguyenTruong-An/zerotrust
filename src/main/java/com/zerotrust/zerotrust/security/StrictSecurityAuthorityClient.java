package com.zerotrust.zerotrust.security;

import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.math.BigDecimal;
import java.util.*;

/** Primary-authority RPC on EVERY authorization. Only the machine credential is cached. */
@Component
public class StrictSecurityAuthorityClient {
    public static final class Rejected extends RuntimeException { public Rejected(){super("SECURITY_STATE_REJECTED");} }
    public static final class Unavailable extends RuntimeException { public Unavailable(){super("SECURITY_AUTHORITY_UNAVAILABLE");} }
    private final Environment environment;
    private final ObjectMapper mapper;
    private final HttpClient http=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1)).followRedirects(HttpClient.Redirect.NEVER).build();
    private volatile String machineToken;
    private volatile Instant machineExpires=Instant.EPOCH;
    private final java.util.concurrent.locks.ReentrantLock tokenRefresh=new java.util.concurrent.locks.ReentrantLock();
    public StrictSecurityAuthorityClient(Environment environment,ObjectMapper mapper){this.environment=environment;this.mapper=mapper;}
    public Map<String,Object> context(Jwt jwt) {
        Object epoch=jwt.getClaims().get("zt_sec_epoch"),version=jwt.getClaims().get("zt_sec_ver");
        String sid=jwt.getClaimAsString("sid"),binding=jwt.getClaimAsString("zt_sec_sid"),client=jwt.getClaimAsString("azp");
        if(sid==null || sid.isBlank() || !sid.equals(binding) || client==null || client.isBlank() || jwt.getSubject()==null || integral(version)!=1) throw new Rejected();
        return Map.of("subjectId",jwt.getSubject(),"sessionId",sid,"clientId",client,"epoch",integral(epoch));
    }
    private long integral(Object value) {
        if(!(value instanceof Number number)) throw new Rejected();
        try {long result=new BigDecimal(number.toString()).longValueExact();if(result<1)throw new Rejected();return result;}
        catch(ArithmeticException | NumberFormatException e){throw new Rejected();}
    }
    public void authorize(Jwt jwt){post("authorizations",context(jwt));}
    private String property(String key) {String value=environment.getProperty("app.security.authority."+key);if(value==null || value.isBlank())throw new Unavailable();return value;}
    private URI uri(String value) {
        URI result=URI.create(value);
        if(!"https".equals(result.getScheme()) || result.getHost()==null || result.getUserInfo()!=null || result.getQuery()!=null || result.getFragment()!=null)throw new Unavailable();
        return result;
    }
    private String machineToken() {
        if(machineToken!=null && Instant.now().plusSeconds(30).isBefore(machineExpires))return machineToken;
        boolean locked=false;
        try {
            locked=tokenRefresh.tryLock(100,java.util.concurrent.TimeUnit.MILLISECONDS);
            if(!locked)throw new Unavailable();
            if(machineToken!=null && Instant.now().plusSeconds(30).isBefore(machineExpires))return machineToken;
            String secret=Files.readString(Path.of(property("secret-file"))).strip();
            String form="grant_type=client_credentials&client_id="+URLEncoder.encode(property("client-id"),StandardCharsets.UTF_8)+"&client_secret="+URLEncoder.encode(secret,StandardCharsets.UTF_8);
            HttpRequest request=HttpRequest.newBuilder(uri(property("token-endpoint"))).timeout(Duration.ofSeconds(3)).header("Content-Type","application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(form)).build();
            var result=exchange(request,false);
            if(!(result.get("access_token") instanceof String token) || token.isBlank() || !"Bearer".equalsIgnoreCase((String)result.get("token_type")) || !(result.get("expires_in") instanceof Number expires) || expires.longValue()<=30)throw new Unavailable();
            machineToken=token;machineExpires=Instant.now().plusSeconds(expires.longValue());return token;
        }catch(Exception failure){if(failure instanceof InterruptedException)Thread.currentThread().interrupt();throw new Unavailable();}
        finally{if(locked)tokenRefresh.unlock();}
    }
    public Map<String,Object> post(String path,Object body) {
        try {
            var request=HttpRequest.newBuilder(uri(property("base-url")).resolve("/internal/v1/security/"+path)).timeout(Duration.ofSeconds(3))
                    .header("Authorization","Bearer "+machineToken()).header("Content-Type","application/json").header("Accept","application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body))).build();
            return exchange(request,true);
        } catch(Rejected | Unavailable failure){throw failure;}
        catch(Exception failure){throw new Unavailable();}
    }
    @SuppressWarnings("unchecked")
    public void nativeEffect(Object effect) {
        try {
            var request=HttpRequest.newBuilder(uri(property("native-effects-url"))).timeout(Duration.ofSeconds(5))
                    .header("Authorization","Bearer "+machineToken()).header("Content-Type","application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(effect))).build();
            exchange(request,false);
        }catch(Exception failure){throw new Unavailable();}
    }
    @SuppressWarnings("unchecked")
    private Map<String,Object> exchange(HttpRequest request,boolean authorization) throws Exception {
        var pending=http.sendAsync(request,info->new LimitedBody());
        HttpResponse<byte[]> response;
        try {response=pending.get(4,java.util.concurrent.TimeUnit.SECONDS);}
        catch(Exception e){pending.cancel(true);if(e instanceof InterruptedException)Thread.currentThread().interrupt();throw new Unavailable();}
            if(authorization && response.statusCode()==409)throw new Rejected();
            if(response.statusCode()==401){synchronized(this){machineToken=null;machineExpires=Instant.EPOCH;}throw new Unavailable();}
            if(response.statusCode()<200 || response.statusCode()>=300)throw new Unavailable();
            if(response.statusCode()==204)return Map.of();
            return mapper.readValue(response.body(),Map.class);
    }
    private static final class LimitedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final java.util.concurrent.CompletableFuture<byte[]> result=new java.util.concurrent.CompletableFuture<>();
        private final java.io.ByteArrayOutputStream bytes=new java.io.ByteArrayOutputStream();
        private java.util.concurrent.Flow.Subscription subscription;
        @Override public java.util.concurrent.CompletionStage<byte[]> getBody(){return result;}
        @Override public void onSubscribe(java.util.concurrent.Flow.Subscription s){subscription=s;s.request(1);}
        @Override public void onNext(java.util.List<java.nio.ByteBuffer> buffers){
            for(var buffer:buffers){if(buffer.remaining()>65536-bytes.size()){subscription.cancel();result.completeExceptionally(new Unavailable());return;}byte[] part=new byte[buffer.remaining()];buffer.get(part);bytes.writeBytes(part);}
            subscription.request(1);
        }
        @Override public void onError(Throwable error){result.completeExceptionally(new Unavailable());}
        @Override public void onComplete(){result.complete(bytes.toByteArray());}
    }
}
