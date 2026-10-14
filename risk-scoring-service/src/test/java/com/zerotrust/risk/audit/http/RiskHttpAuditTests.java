package com.zerotrust.risk.audit.http;

import com.zerotrust.risk.entity.*;
import com.zerotrust.risk.domain.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.dao.*;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Stream;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@EnabledIfSystemProperty(named="qa.http.audit",matches="true")
@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@org.springframework.context.annotation.Import(HttpDispatchTrace.class)
class RiskHttpAuditTests extends HttpAuditSupport {
    @AfterAll static void stopJwks() {
        System.out.println("QA01D JWKS public-key fetches="+HttpJwtFixture.FETCHES.get());
        HttpJwtFixture.JWKS.stop(0);
    }
    static Stream<Arguments> missing() {return Stream.of("evaluation","registration","failure","success","revoke","completion").map(Arguments::of);}
    String path(String name,String subject) {
        return switch(name) {case "evaluation"->EVAL;case "registration"->REG;case "failure"->FAIL;case "success"->SUCCESS;
            case "revoke"->revoke(subject);default->revoke(subject)+"/completion";};
    }
    @ParameterizedTest @MethodSource("missing")
    void allSixMutationPathsRejectMissingAuthenticationWithoutEffects(String endpoint) throws Exception {
        String p=path(endpoint,id());var before=db();
        assertThat(post(p,null,body(p,id())).statusCode()).isEqualTo(401);unchanged(before);
    }
    static Stream<Arguments> matrix() {
        return Stream.of("evaluation","registration","failure","success","revoke","completion")
                .flatMap(e->Stream.of("spa","wrong-role","other-supported-role","realm-role","other-resource","wrong-client-all-roles","malformed-roles")
                        .map(v->Arguments.of(e,v)));
    }
    @ParameterizedTest @MethodSource("matrix")
    void signedUnauthorizedClientRoleMatrixCannotMutate(String endpoint,String variant) throws Exception {
        String p=path(endpoint,id());boolean admin=endpoint.equals("revoke")||endpoint.equals("completion");
        var c=HttpJwtFixture.claims(admin?HttpJwtFixture.ADMIN:HttpJwtFixture.CALLER,
                "risk:evaluate","risk:device:write","risk:events:write","risk:device:revoke");
        switch(variant) {
            case "spa"->c.claim("azp","zerotrust-spa");
            case "wrong-role"->c.claim("resource_access",Map.of(HttpJwtFixture.AUD,Map.of("roles",List.of("ADMIN"))));
            case "other-supported-role"->c.claim("resource_access",Map.of(HttpJwtFixture.AUD,Map.of("roles",List.of(endpoint.equals("registration")||endpoint.equals("failure")||endpoint.equals("success")?"risk:evaluate":"risk:device:write"))));
            case "realm-role"->c.claim("resource_access",Map.of()).claim("realm_access",Map.of("roles",List.of("risk:device:revoke","risk:evaluate","risk:device:write","risk:events:write")));
            case "other-resource"->c.claim("resource_access",Map.of("other-api",Map.of("roles",List.of("risk:device:revoke","risk:evaluate","risk:device:write","risk:events:write"))));
            case "wrong-client-all-roles"->c.claim("azp",admin?HttpJwtFixture.CALLER:HttpJwtFixture.ADMIN);
            default->c.claim("resource_access",Map.of(HttpJwtFixture.AUD,Map.of("roles","risk:evaluate")));
        }
        var before=db();assertThat(post(p,HttpJwtFixture.sign(c,HttpJwtFixture.KEY),body(p,id())).statusCode()).isEqualTo(403);
        unchanged(before);
    }
    @ParameterizedTest @ValueSource(strings={"empty","malformed","bad-signature","tampered","expired","future","issuer","missing-issuer","audience","missing-audience","missing-expiry","bad-audience-type","bad-expiry-type","missing-azp","numeric-azp","bad-resources"})
    void realSignatureAndClaimNegativesRejectBeforePersistence(String variant) throws Exception {
        var c=HttpJwtFixture.claims(HttpJwtFixture.CALLER,"risk:device:write");
        int expected=401;String token;
        switch(variant) {
            case "expired"->c.expirationTime(Date.from(Instant.now().minusSeconds(120)));
            case "future"->c.notBeforeTime(Date.from(Instant.now().plusSeconds(120)));
            case "issuer"->c.issuer("https://wrong.invalid");case "missing-issuer"->c.issuer(null);
            case "audience"->c.audience("other-api");case "missing-audience"->c.audience((String)null);
            case "missing-expiry"->c.expirationTime(null);
            case "bad-audience-type"->c.claim("aud",42);
            case "bad-expiry-type"->c.claim("exp","not-a-time");
            case "missing-azp"->{c.claim("azp",null);expected=403;}
            case "numeric-azp"->{c.claim("azp",42);expected=403;}
            case "bad-resources"->{c.claim("resource_access","invalid");expected=403;}
        }
        if(variant.equals("empty"))token="RAW:Bearer ";
        else if(variant.equals("malformed"))token="x.y.z";
        else if(variant.equals("bad-signature"))token=HttpJwtFixture.sign(c,HttpJwtFixture.WRONG);
        else {token=HttpJwtFixture.sign(c,HttpJwtFixture.KEY);if(variant.equals("tampered")) {
            String[] parts=token.split("\\.");
            String payload=new String(Base64.getUrlDecoder().decode(parts[1]),java.nio.charset.StandardCharsets.UTF_8)
                    .replace("synthetic-service-account","tampered-service-account");
            token=parts[0]+"."+Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8))+"."+parts[2];
        }}
        var before=db();var r=post(REG,token,reg(id(),0));assertThat(r.statusCode()).as(variant).isEqualTo(expected);
        if(expected==401)assertThat(r.headers().firstValue("www-authenticate")).contains("Bearer");
        unchanged(before);
    }
    @Test void delegatedServiceSubjectAndMissingJwtSubjectAreCharacterized() throws Exception {
        String subject=id();trusted(subject);
        assertThat(devices.findAllBySubjectId(subject)).hasSize(1);
        var c=HttpJwtFixture.claims(HttpJwtFixture.CALLER,"risk:device:write").subject(null);
        assertThat(post(REG,HttpJwtFixture.sign(c,HttpJwtFixture.KEY),reg(id(),0)).statusCode()).isEqualTo(204);
        assertThat(HttpJwtFixture.FETCHES.get()).isPositive();
        // This is a delegated service contract, not a subject-equality security oracle.
    }
    @ParameterizedTest @ValueSource(strings={"none","RS512"})
    void unsupportedAlgorithmsCannotMutateDespiteMatchingClaims(String algorithm) throws Exception {
        var claims=HttpJwtFixture.claims(HttpJwtFixture.CALLER,"risk:device:write").build();String token;
        if(algorithm.equals("none"))token=new com.nimbusds.jwt.PlainJWT(claims).serialize();
        else {
            var jwt=new com.nimbusds.jwt.SignedJWT(new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS512).keyID(HttpJwtFixture.KEY.getKeyID()).build(),claims);
            jwt.sign(new com.nimbusds.jose.crypto.RSASSASigner(HttpJwtFixture.KEY));token=jwt.serialize();
        }
        var before=db();assertThat(post(REG,token,reg(id(),0)).statusCode()).isEqualTo(401);unchanged(before);
    }
    @ParameterizedTest @ValueSource(strings={"missing","negative","missing-device","blank-subject"})
    void registrationBeanConstraintsAre400AndMutationFree(String variant) throws Exception {
        var b=new HashMap<String,Object>();b.put("subjectId",id());b.put("deviceId",DEVICE);b.put("trustGeneration",0);
        switch(variant){case "missing"->b.remove("trustGeneration");case "negative"->b.put("trustGeneration",-1);case "missing-device"->b.remove("deviceId");default->b.put("subjectId"," ");}
        var before=db();assertThat(post(REG,allowed(REG),json(b)).statusCode()).isEqualTo(400);unchanged(before);
    }
    @Test void actualH2ConstraintViolationRollsBackRegistrationAndMustRemainServerError() throws Exception {
        String s=id();
        // Fixture-only constraint in a random in-memory database; no production migration is modified.
        jdbc.execute("ALTER TABLE known_devices ADD CONSTRAINT qa01d_reject CHECK (subject_id <> '"+s+"')");
        var before=db();var r=post(REG,allowed(REG),reg(s,0));
        assertThat(db()).isEqualTo(before);assertThat(devices.findAllBySubjectId(s)).isEmpty();verifyNoInteractions(redis);
        assertThat(r.statusCode()).isBetween(500,599);
    }
    @ParameterizedTest @ValueSource(strings={"null-subject","blank-subject","overlong-subject","missing-session","overlong-agent","overlong-device","invalid-ip","mapped-ip","zone-ip","hostname-ip","overlong-ip"})
    void evaluationBeanConstraintsReturn400AndDoNotCreateSubjectState(String variant) throws Exception {
        var b=new HashMap<String,Object>();b.put("subjectId",id());b.put("authenticationSessionId","session");b.put("clientId",CLIENT);b.put("ipAddress","10.1.2.3");
        switch(variant) {
            case "null-subject"->b.put("subjectId",null);case "blank-subject"->b.put("subjectId","  ");
            case "overlong-subject"->b.put("subjectId","x".repeat(256));case "missing-session"->b.remove("authenticationSessionId");
            case "overlong-agent"->b.put("userAgent","x".repeat(1025));case "overlong-device"->b.put("deviceId","x".repeat(256));
            case "mapped-ip"->b.put("ipAddress","::ffff:192.0.2.1");case "zone-ip"->b.put("ipAddress","fe80::1%eth0");
            case "hostname-ip"->b.put("ipAddress","localhost");case "overlong-ip"->b.put("ipAddress","1".repeat(46));
            default->b.put("ipAddress","999.1.2.3");
        }
        var before=db();assertThat(post(EVAL,allowed(EVAL),json(b)).statusCode()).isEqualTo(400);unchanged(before);
    }
    @ParameterizedTest @ValueSource(strings={"malformed-json","object-subject","array-ip","invalid-timestamp","invalid-generation","uuid-path","invalid-operation"})
    void authorizedMessageConversionErrorsMustRemain400(String variant) throws Exception {
        String p=EVAL,b=body(p,id());
        switch(variant) {
            case "malformed-json"->b="{";
            case "object-subject"->b=b.replaceFirst("\"subjectId\":\"[^\"]+\"","\"subjectId\":{}");
            case "array-ip"->b=b.replaceFirst("\"ipAddress\":\"[^\"]+\"","\"ipAddress\":[]");
            case "invalid-timestamp"->{p=SUCCESS;b=body(p,id()).replaceFirst("\"authenticatedAt\":\"[^\"]+\"","\"authenticatedAt\":\"not-a-time\"");}
            case "invalid-generation"->{p=REG;b="{\"subjectId\":\"user\",\"deviceId\":\"device\",\"trustGeneration\":\"not-a-number\"}";}
            case "uuid-path"->{p=revoke("not-a-uuid");b=operation(id(),"qa-admin");}
            case "invalid-operation"->{p=revoke(id());b="{\"operationId\":\"bad-uuid\",\"requestedBy\":\"qa-admin\"}";}
        }
        var before=db();var r=post(p,allowed(p),b);unchanged(before);
        assertThat(HttpDispatchTrace.RECORDS).anyMatch(d->d.type()==jakarta.servlet.DispatcherType.ERROR && Integer.valueOf(400).equals(d.originalStatus()));
        assertThat(r.statusCode()).as(variant).isEqualTo(400);
    }
    @Test void unknownAndDuplicateJsonFieldsAreCharacterizedWithFinalValue() throws Exception {
        String subject=id();var b=reg(subject,0).replace("}",",\"mfaCompleted\":false,\"decision\":\"UNKNOWN_ENUM\"}");
        assertThat(post(REG,allowed(REG),b).statusCode()).isEqualTo(204);
        String duplicate="{\"subjectId\":\"discarded\",\"subjectId\":\""+id()+"\",\"deviceId\":\"qa-device\",\"trustGeneration\":0}";
        assertThat(post(REG,allowed(REG),duplicate).statusCode()).isEqualTo(204);
        assertThat(devices.findAllBySubjectId("discarded")).isEmpty();
    }
    @Test void lifecycleGenerationPendingCompletionAndSecurityRevocation() throws Exception {
        String s=id(),op=id(),p=revoke(s);trusted(s);
        String b=operation(op,"qa-admin");
        assertThat(post(p,allowed(p),b).statusCode()).isEqualTo(204);
        assertThat(post(p,allowed(p),b).statusCode()).isEqualTo(204);
        assertThat(post(REG,allowed(REG),reg(s,0)).statusCode()).isEqualTo(409);
        assertThat(post(REG,allowed(REG),reg(s,1)).statusCode()).isEqualTo(409);
        var pending=node(post(EVAL,allowed(EVAL),evaluation(s,"10.1.2.3")));
        assertThat(pending.path("decision").asText()).isEqualTo("DENY");assertThat(pending.path("trustGeneration").asLong()).isEqualTo(1);
        for(String wrong:List.of(operation(op,"other-requester"),operation(id(),"qa-admin")))
            assertThat(post(p+"/completion",allowed(p),wrong).statusCode()).isEqualTo(409);
        assertThat(post(p+"/completion",allowed(p),b).statusCode()).isEqualTo(204);
        assertThat(post(REG,allowed(REG),reg(s,0)).statusCode()).isEqualTo(409);
        assertThat(post(REG,allowed(REG),reg(s,1)).statusCode()).isEqualTo(409); // old revoked cookie must rotate
        String fresh=json(Map.of("subjectId",s,"deviceId","fresh-device","trustGeneration",1));
        assertThat(post(REG,allowed(REG),fresh).statusCode()).isEqualTo(204);
        String op2=id(),b2=operation(op2,"qa-admin");assertThat(post(p,allowed(p),b2).statusCode()).isEqualTo(204);
        assertThat(post(p+"/completion",allowed(p),b).statusCode()).isEqualTo(204); // idempotent old completion does not clear new pending
        assertThat(lifecycle.snapshot(s).resetPending()).isTrue();assertThat(lifecycle.generation(s)).isEqualTo(2);
        assertThat(post(p+"/completion",allowed(p),b2).statusCode()).isEqualTo(204);
        String sec=id();trusted(sec);var device=devices.findAllBySubjectId(sec).get(0);device.revoke(Instant.now());devices.saveAndFlush(device);
        String secp=revoke(sec),secb=operation(id(),"qa-admin");post(secp,allowed(secp),secb);post(secp+"/completion",allowed(secp),secb);
        assertThat(post(REG,allowed(REG),reg(sec,1)).statusCode()).isEqualTo(409);
        assertThat(node(post(EVAL,allowed(EVAL),evaluation(sec,"10.1.2.3"))).path("decision").asText()).isEqualTo("DENY");
    }
    @Test void requesterIsDelegatedBodyDataButOperationOwnerCannotChange() throws Exception {
        String s=id(),op=id(),p=revoke(s);
        assertThat(post(p,allowed(p),operation(op,"body-admin-not-jwt-sub")).statusCode()).isEqualTo(204);
        assertThat(post(p+"/completion",allowed(p),operation(op,"synthetic-service-account")).statusCode()).isEqualTo(409);
        assertThat(post(p+"/completion",allowed(p),operation(op,"body-admin-not-jwt-sub")).statusCode()).isEqualTo(204);
    }
    @Test void canonicalAndPaddedRegistrationEvaluationMustShareTrustIdentity() throws Exception {
        String s=id();history(s,6);trusted(" "+s+" ");
        var canonical=node(post(EVAL,allowed(EVAL),evaluation(s,"10.1.2.3")));
        var padded=node(post(EVAL,allowed(EVAL),evaluation(" "+s+" ","10.1.2.3")));
        System.out.println("QA01D KNOWN BUG-01B-01 canonical="+canonical+" padded="+padded);
        assertThat(canonical.path("decision").asText()).isEqualTo("ALLOW");
        assertThat(padded.path("decision").asText()).isEqualTo(canonical.path("decision").asText());
    }
    @Test void uuidResetPathCanonicalizesPaddingAndNoOuterTransactionIsAdded() throws Exception {
        String s=id();trusted(" "+s+" ");String b=operation(id(),"qa-admin");
        var r=post(revoke("%20"+s+"%20"),allowed(revoke(s)),b);
        assertThat(r.statusCode()).isEqualTo(204);
        assertThat(devices.findAllBySubjectId(s).get(0).getStatus()).isEqualTo(DeviceStatus.REVOKED);
        assertThat(lifecycle.snapshot(s).resetPending()).isTrue();
        assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
        assertThat(HttpDispatchTrace.RECORDS).anyMatch(d->d.uri().contains(s)&&d.type()==jakarta.servlet.DispatcherType.REQUEST&&!d.transactionAtEntry());
        // Current production controllers have no transaction wrapper; this does not emulate RR snapshots.
    }
    @Test void equivalentIpv6HttpInputsMustKeepSameDecision() throws Exception {
        String s=id();history(s,0);subjects.put(s,5L);
        var hex=node(post(EVAL,allowed(EVAL),evaluation(s,"2001:db8::c000:201")));
        var mixed=node(post(EVAL,allowed(EVAL),evaluation(s,"2001:db8::192.0.2.1")));
        assertThat(com.zerotrust.risk.validation.IpAddressNormalizer.normalize("2001:db8::192.0.2.1"))
                .isEqualTo(com.zerotrust.risk.validation.IpAddressNormalizer.normalize("2001:db8::c000:201"));
        System.out.println("QA01D KNOWN BUG-01A-02 hex="+hex+" mixed="+mixed);
        assertThat(hex.path("decision").asText()).isEqualTo("DENY");
        assertThat(mixed.path("decision").asText()).isEqualTo(hex.path("decision").asText());
    }
    @Test void temporalPrecisionOracleThroughHttpMustApplyAcceptedMinimum() throws Exception {
        String s=id();history(s,4);trusted(s);subjects.put(s,3L);
        var result=node(post(EVAL,allowed(EVAL),evaluation(s,"203.0.113.10")));
        System.out.println("QA01D KNOWN BUG-01A-01 4/6 < .6666668 expected=MFA/50 actual="+result);
        assertThat(result.path("decision").asText()).isEqualTo("STEP_UP_MFA");
        assertThat(result.path("riskScore").decimalValue()).isEqualByComparingTo("50");
    }
    @Test void suppliedIpAndProxyHeadersDoNotOverridePayloadOrGrantAccess() throws Exception {
        String s=id(),event=id();String b=json(Map.of("eventId",event,"subjectId",s,"sourceIp","203.0.113.10"));
        assertThat(call("POST",FAIL,allowed(FAIL),b,"X-Forwarded-For","10.1.2.3","Forwarded","for=10.1.2.3;proto=https").statusCode()).isEqualTo(204);
        verify(redis).recordFailure(event,s,"203.0.113.10");assertThat(ips.get("10.1.2.3")).isNull();
        reset(redis);var before=db();
        assertThat(call("POST",REG,null,reg(id(),0),"X-Forwarded-Proto","https","X-Forwarded-For","127.0.0.1").statusCode()).isEqualTo(401);
        assertThat(db()).isEqualTo(before);verifyNoInteractions(redis);
    }
    @Test void successEventReplayDifferentPayloadPreservesFirstSqlRecord() throws Exception {
        String event=id(),s=id();String b=json(Map.of("eventId",event,"subjectId",s,"clientId",CLIENT,"authenticatedAt",Instant.now().minusSeconds(30).toString()));
        assertThat(post(SUCCESS,allowed(SUCCESS),b).statusCode()).isEqualTo(204);
        assertThat(post(SUCCESS,allowed(SUCCESS),b.replace(s,id())).statusCode()).isEqualTo(204);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM authentication_success_events WHERE event_id=?",Integer.class,event)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT subject_id FROM authentication_success_events WHERE event_id=?",String.class,event)).isEqualTo(s);
    }
    @ParameterizedTest @ValueSource(strings={"refused","timeout","lua","malformed-counter"})
    void injectedRedisFaultKeepsEvaluationIncompleteAndEventErrorIsServerFailure(String fault) throws Exception {
        String s=id();history(s,6);trusted(s);
        DataAccessException problem=switch(fault){case "refused"->new org.springframework.data.redis.RedisConnectionFailureException("synthetic fault");case "timeout"->new QueryTimeoutException("synthetic fault");default->new DataRetrievalFailureException("synthetic fault");};
        when(redis.countBySubject(anyString())).thenThrow(problem);
        var evaluation=node(post(EVAL,allowed(EVAL),evaluation(s,"10.1.2.3")));
        assertThat(evaluation.path("decision").asText()).isEqualTo("STEP_UP_MFA");assertThat(evaluation.path("dataStatus").asText()).isEqualTo("INCOMPLETE");
        doThrow(problem).when(redis).recordFailure(anyString(),nullable(String.class),anyString());
        var before=db();var r=post(FAIL,allowed(FAIL),body(FAIL,s));
        assertThat(db()).isEqualTo(before);assertThat(events).isEmpty();assertThat(subjects).isEmpty();assertThat(ips).isEmpty();
        assertThat(HttpDispatchTrace.RECORDS).anyMatch(d->d.type()==jakarta.servlet.DispatcherType.ERROR && Integer.valueOf(500).equals(d.originalStatus()));
        assertThat(r.statusCode()).as("authorized dependency failure must retain 5xx classification").isBetween(500,599);
    }
    @Test void concurrentSameOperationHttpRetryCommitsOnlyOneGenerationAndAudit() throws Exception {
        String s=id(),op=id(),p=revoke(s),token=allowed(p),b=operation(op,"qa-admin");trusted(s);
        var ready=new CyclicBarrier(2);var pool=Executors.newFixedThreadPool(2);
        try {
            Callable<Integer> task=()->{ready.await(5,TimeUnit.SECONDS);return post(p,token,b).statusCode();};
            var a=pool.submit(task);var c=pool.submit(task);assertThat(a.get(10,TimeUnit.SECONDS)).isEqualTo(204);assertThat(c.get(10,TimeUnit.SECONDS)).isEqualTo(204);
        }finally{pool.shutdownNow();}
        assertThat(lifecycle.generation(s)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM device_trust_revocations WHERE subject_id=?",Integer.class,s)).isEqualTo(1);
        assertThat(devices.findAllBySubjectId(s).get(0).getStatus()).isEqualTo(DeviceStatus.REVOKED);
    }
    @Test void differentOperationHttpRaceCannotBeCompletedByOlderOperation() throws Exception {
        String s=id(),p=revoke(s),token=allowed(p),a=id(),b=id();trusted(s);
        var barrier=new CyclicBarrier(2);var pool=Executors.newFixedThreadPool(2);
        try {
            var f=pool.submit(()->{barrier.await(5,TimeUnit.SECONDS);return post(p,token,operation(a,"qa-admin")).statusCode();});
            var g=pool.submit(()->{barrier.await(5,TimeUnit.SECONDS);return post(p,token,operation(b,"qa-admin")).statusCode();});
            assertThat(f.get(10,TimeUnit.SECONDS)).isEqualTo(204);assertThat(g.get(10,TimeUnit.SECONDS)).isEqualTo(204);
        }finally{pool.shutdownNow();}
        String pending=jdbc.queryForObject("SELECT pending_operation_id FROM subject_device_trust WHERE subject_id=?",String.class,s);
        String older=pending.equals(a)?b:a;
        assertThat(post(p+"/completion",token,operation(older,"qa-admin")).statusCode()).isEqualTo(409);
        assertThat(lifecycle.generation(s)).isEqualTo(2);assertThat(lifecycle.snapshot(s).resetPending()).isTrue();
        assertThat(post(p+"/completion",token,operation(pending,"qa-admin")).statusCode()).isEqualTo(204);
    }
    @Test void unspecifiedPathsMethodsAndHealthStayWithinSecurityContract() throws Exception {
        var before=db();String t=allowed(EVAL);
        assertThat(call("GET",EVAL,t,"").statusCode()).isEqualTo(403);
        assertThat(call("GET","/actuator/info",t,"").statusCode()).isEqualTo(403);
        assertThat(call("GET","/actuator/health",null,"").statusCode()).isEqualTo(200);
        assertThat(call("OPTIONS",REG,null,"","Origin","https://untrusted.invalid","Access-Control-Request-Method","POST").statusCode()).isEqualTo(401);
        unchanged(before);
    }
}
