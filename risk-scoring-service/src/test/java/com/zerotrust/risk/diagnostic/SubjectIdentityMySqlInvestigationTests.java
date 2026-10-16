package com.zerotrust.risk.diagnostic;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.repository.*;
import com.zerotrust.risk.service.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.assertj.core.api.SoftAssertions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.*;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

// PROPOSED, NOT RUN. One approved pair per invocation; report observations BEFORE contract assertions.
@EnabledIfSystemProperty(named="postfix03a.gateB",matches="APPROVED")
@SpringBootTest(properties={"spring.datasource.url=${PF03A_MYSQL_URL}","spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver","spring.datasource.username=pf03a_app","spring.datasource.password=${PF03A_MYSQL_PASSWORD}","spring.jpa.hibernate.ddl-auto=validate","spring.flyway.enabled=false","spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration,org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration"})
@ActiveProfiles("test")
@ContextConfiguration(initializers=SubjectIdentityMySqlSupport.class)
@Import(SubjectIdentityMySqlSupport.TimeConfig.class)
class SubjectIdentityMySqlInvestigationTests {
 @Autowired TrustedDeviceRegistrationService registration;
 @Autowired DeviceTrustLifecycle lifecycle;
 @Autowired KnownDeviceRepository devices;
 @Autowired DeviceRecognitionService recognition;
 @Autowired DeviceFingerprintHasher deviceHasher;
 @Autowired AuthenticationHistoryKeyHasher historyHasher;
 @Autowired JdbcTemplate jdbc;
 @MockitoBean RedisAuthenticationFailureStore redis;
 String recognize(String s,String d){return recognition.recognize(new LoginContext(s,"qa02b-session","qa02b-client","192.0.2.3",null,d,SubjectIdentityMySqlSupport.NOW.get())).status().name();}
 Map<String,Object> state(String a,String b,String d){var m=new LinkedHashMap<String,Object>();m.put("generation_A",lifecycle.generation(a));m.put("generation_B",lifecycle.generation(b));m.put("recognition_A",recognize(a,d));m.put("recognition_B",recognize(b,d));m.put("repository_subject_count_A",devices.findAllBySubjectId(a).size());m.put("repository_subject_count_B",devices.findAllBySubjectId(b).size());m.put("state_rows",jdbc.queryForList("SELECT subject_id,generation,pending_operation_id FROM subject_device_trust WHERE BINARY subject_id IN (BINARY ?,BINARY ?)",a,b));m.put("device_rows",jdbc.queryForList("SELECT subject_id,status,revocation_reason,version FROM known_devices WHERE BINARY subject_id IN (BINARY ?,BINARY ?)",a,b));m.put("audits",jdbc.queryForList("SELECT subject_id,generation,revoked_count,completed_at FROM device_trust_revocations WHERE BINARY subject_id IN (BINARY ?,BINARY ?)",a,b).stream().map(x->{var y=new LinkedHashMap<String,Object>();x.forEach((k,v)->y.put(k,v==null?null:v.toString()));return y;}).toList());return m;}
 @Test void controlledPairUsesIndependentOpaqueSubjectOracle()throws Exception {
  String scope=System.getProperty("diagnosticScope"),caseId=System.getProperty("postfix02.case");var pairs=(List<Map<String,Object>>)SubjectIdentityMySqlSupport.manifest().get("identity_pairs");var pair=pairs.stream().filter(x->scope.equals(x.get("scope"))&&caseId.equals(x.get("case"))).findFirst().orElseThrow();
  String a=pair.get("left").toString(),b=pair.get("right").toString(),d=pair.get("device").toString();UUID op=UUID.fromString(pair.get("operation").toString());SubjectIdentityMySqlSupport.own(a);SubjectIdentityMySqlSupport.own(b);
  SubjectIdentityMySqlSupport.NOW.set(Instant.parse("2026-10-15T00:00:00.123456Z"));var out=new LinkedHashMap<String,Object>();out.put("scope",scope);out.put("case",caseId);out.put("fixture",pair);out.put("runtime_keycloak_calls",0);out.put("device_hmac_equal",deviceHasher.hash(a,d).equals(deviceHasher.hash(b,d)));out.put("history_hmac_equal",historyHasher.hash("subject",a).equals(historyHasher.hash("subject",b)));
  registration.trustAfterMfa(a,d,0);out.put("recognition_B_before_registration",recognize(b,d));assertThat(recognize(b,d)).isEqualTo("NEW");
  out.put("B_lookup_using_A_digest",devices.findBySubjectIdAndDeviceFingerprintHash(b,deviceHasher.hash(a,d)).isPresent());
  registration.trustAfterMfa(b,d,0);out.put("after_independent_registrations",state(a,b,d));
  lifecycle.revoke(a,op,"qa02b-admin");var afterA=state(a,b,d);out.put("after_revoke_A",afterA);
  assertThatThrownBy(()->lifecycle.complete(b,op,"qa02b-admin")).isInstanceOf(com.zerotrust.risk.exception.DeviceTrustRejectedException.class); // exact audit owner guard
  lifecycle.complete(a,op,"qa02b-admin");UUID opB=UUID.randomUUID();lifecycle.revoke(b,opB,"qa02b-admin");lifecycle.complete(b,opB,"qa02b-admin");out.put("after_revoke_B_complete",state(a,b,d));
  Files.writeString(Path.of(System.getProperty("identityOutput")),new ObjectMapper().writeValueAsString(out));System.out.println("POSTFIX02_NATIVE_IDENTITY "+new ObjectMapper().writeValueAsString(out));
  var contract=new SoftAssertions();contract.assertThat(afterA.get("generation_B")).as("independent subject B generation after revoke A").isEqualTo(0L);contract.assertThat(afterA.get("recognition_B")).as("independent B remains trusted").isEqualTo("TRUSTED");contract.assertThat(afterA.get("repository_subject_count_B")).as("B subject-only lookup owns one row").isEqualTo(1);contract.assertThat((List<?>)afterA.get("state_rows")).as("two independent state rows").hasSize(2);contract.assertAll();
 }
}
