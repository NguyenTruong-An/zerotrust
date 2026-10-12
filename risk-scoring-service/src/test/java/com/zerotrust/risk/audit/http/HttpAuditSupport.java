package com.zerotrust.risk.audit.http;

import com.fasterxml.jackson.databind.*;
import com.zerotrust.risk.repository.*;
import com.zerotrust.risk.service.*;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import java.net.URI;
import java.net.http.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Live servlet/security/JPA; Redis boundary is explicitly a controlled mock because QA was removed. */
abstract class HttpAuditSupport {
    static final String EVAL="/internal/v1/risk/evaluations", REG="/internal/v1/trusted-devices";
    static final String FAIL="/internal/v1/authentication-failures", SUCCESS="/internal/v1/authentication-successes";
    static final String DEVICE="qa-device", CLIENT="qa-client";
    static final String RUN=UUID.randomUUID().toString();
    @LocalServerPort int port;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;
    @Autowired KnownDeviceRepository devices;
    @Autowired DeviceFingerprintHasher hasher;
    @Autowired DeviceTrustLifecycle lifecycle;
    @MockitoBean RedisAuthenticationFailureStore redis;
    final Map<String,Long> subjects=new ConcurrentHashMap<>(), ips=new ConcurrentHashMap<>();
    final Set<String> events=ConcurrentHashMap.newKeySet();
    final AtomicInteger writes=new AtomicInteger();
    static final HttpClient HTTP=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3))
            .followRedirects(HttpClient.Redirect.NEVER).build();

    @DynamicPropertySource static void settings(DynamicPropertyRegistry p) {
        p.add("server.address",()->"127.0.0.1"); p.add("server.ssl.enabled",()->false);
        p.add("server.forward-headers-strategy",()->"none");
        p.add("spring.datasource.url",()->"jdbc:h2:mem:qa01d_"+RUN+";MODE=MySQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE");
        p.add("spring.datasource.driver-class-name",()->"org.h2.Driver");
        p.add("spring.datasource.username",()->"sa"); p.add("spring.datasource.password",()->"");
        p.add("spring.autoconfigure.exclude",()->String.join(",",
                "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration",
                "org.springframework.boot.autoconfigure.data.redis.RedisReactiveAutoConfiguration",
                "org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration"));
        p.add("spring.data.redis.host",()->"127.0.0.1"); p.add("spring.data.redis.port",()->6380);
        p.add("spring.data.redis.ssl.enabled",()->false);
        p.add("risk.authentication-history.key-prefix",()->"qa01d:"+RUN);
        p.add("risk.authentication-history.pepper",()->"qa01d-only-synthetic-history-pepper");
        p.add("risk.device-fingerprint.pepper",()->"qa01d-only-synthetic-device-pepper");
        p.add("risk.security.issuer-uri",()->HttpJwtFixture.ISSUER);
        p.add("risk.security.jwk-set-uri",HttpJwtFixture::jwks);
        p.add("risk.security.audience",()->HttpJwtFixture.AUD);
        p.add("risk.security.allowed-client-id",()->HttpJwtFixture.CALLER);
        p.add("risk.security.revoke-client-id",()->HttpJwtFixture.ADMIN);
        p.add("risk.security.require-https",()->false);
        p.add("risk.policy.network-risk.enabled",()->true);
        p.add("risk.policy.network-risk.default-score",()->50);
        p.add("risk.policy.network-risk.trusted-cidrs",()->"10.0.0.0/8");
        p.add("risk.policy.network-risk.high-risk-cidrs",()->"2001:db8::/32");
        p.add("risk.policy.temporal-risk.minimum-day-frequency",()->"0.6666668");
        p.add("risk.policy.temporal-risk.minimum-hour-frequency",()->"0.6666668");
    }
    @BeforeEach void boundary() {
        reset(redis); subjects.clear(); ips.clear(); events.clear(); writes.set(0);
        when(redis.countBySubject(anyString())).thenAnswer(i->subjects.getOrDefault(i.getArgument(0),0L));
        when(redis.countBySourceIp(anyString())).thenAnswer(i->ips.getOrDefault(i.getArgument(0),0L));
        when(redis.recordFailure(anyString(), nullable(String.class), anyString())).thenAnswer(i->{
            writes.incrementAndGet();
            String event=i.getArgument(0), subject=i.getArgument(1), ip=i.getArgument(2);
            if(!events.add(event)) return false;
            if(subject!=null) subjects.merge(subject,1L,Long::sum); ips.merge(ip,1L,Long::sum); return true;
        });
        assertThat(jdbc.queryForObject("SELECT H2VERSION()",String.class)).startsWith("2.");
    }
    String id() { return UUID.randomUUID().toString(); }
    String revoke(String subject) { return "/internal/v1/subjects/"+subject+"/trusted-devices/revocations"; }
    String json(Object value) throws Exception {return mapper.writeValueAsString(value);}
    String reg(String subject,long generation) throws Exception {
        return json(Map.of("subjectId",subject,"deviceId",DEVICE,"trustGeneration",generation));
    }
    String evaluation(String subject,String ip) throws Exception {
        return json(Map.of("subjectId",subject,"authenticationSessionId","qa-session","clientId",CLIENT,
                "ipAddress",ip,"deviceId",DEVICE));
    }
    String operation(String op,String requester) throws Exception { return json(Map.of("operationId",op,"requestedBy",requester)); }
    String allowed(String path) throws Exception {
        return path.startsWith("/internal/v1/subjects/") ? HttpJwtFixture.token(HttpJwtFixture.ADMIN,"risk:device:revoke")
                : HttpJwtFixture.token(HttpJwtFixture.CALLER,path.equals(EVAL)?"risk:evaluate":path.equals(REG)?"risk:device:write":"risk:events:write");
    }
    String body(String path,String subject) throws Exception {
        if(path.equals(EVAL))return evaluation(subject,"10.1.2.3");
        if(path.equals(REG))return reg(subject,0);
        if(path.equals(FAIL))return json(Map.of("eventId",id(),"subjectId",subject,"sourceIp","203.0.113.10"));
        if(path.equals(SUCCESS))return json(Map.of("eventId",id(),"subjectId",subject,"clientId",CLIENT,"authenticatedAt",Instant.now().minusSeconds(60).toString()));
        return operation(id(),"qa-admin");
    }
    HttpResponse<String> call(String method,String path,String token,String body,String... headers) throws Exception {
        var req=HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+path)).timeout(Duration.ofSeconds(10))
                .header("Content-Type","application/json");
        if(token!=null)req.header("Authorization",token.startsWith("RAW:")?token.substring(4):"Bearer "+token);
        for(int i=0;i<headers.length;i+=2)req.header(headers[i],headers[i+1]);
        var response=HTTP.send(req.method(method,HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofString());
        System.out.println("QA01D HTTP method="+method+" path="+path+" status="+response.statusCode()+" body="+response.body());
        assertThat(response.headers().firstValue("set-cookie")).isEmpty();
        assertThat(response.body()).doesNotContain("java.lang.","password","stackTrace","access_token");
        return response;
    }
    HttpResponse<String> post(String path,String token,String body) throws Exception {return call("POST",path,token,body);}
    JsonNode node(HttpResponse<String> response) throws Exception {return mapper.readTree(response.body());}
    List<Long> db() {return List.of("known_devices","subject_device_trust","device_trust_revocations","authentication_success_events")
            .stream().map(t->jdbc.queryForObject("SELECT COUNT(*) FROM "+t,Long.class)).toList();}
    void unchanged(List<Long> before) {assertThat(db()).isEqualTo(before);verifyNoInteractions(redis);assertThat(writes.get()).isZero();}
    void history(String subject,int matches) throws Exception {
        var now=ZonedDateTime.now(ZoneOffset.UTC);
        for(int i=1;i<=6;i++) {
            var when=now.minusWeeks(i);
            if(i>matches)when=when.minusDays(1).minusHours(6);
            String b=json(Map.of("eventId",id(),"subjectId",subject,"clientId",CLIENT,"authenticatedAt",when.toInstant().toString()));
            assertThat(post(SUCCESS,allowed(SUCCESS),b).statusCode()).isEqualTo(204);
        }
    }
    void trusted(String subject) throws Exception {assertThat(post(REG,allowed(REG),reg(subject,0)).statusCode()).isEqualTo(204);}
}
