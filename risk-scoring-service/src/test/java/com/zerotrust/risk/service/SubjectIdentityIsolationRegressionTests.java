package com.zerotrust.risk.service;

import com.zerotrust.risk.domain.LoginContext;
import com.zerotrust.risk.domain.SubjectIdentifierNormalizer;
import com.zerotrust.risk.exception.DeviceTrustRejectedException;
import com.zerotrust.risk.repository.KnownDeviceRepository;
import com.zerotrust.risk.repository.RedisAuthenticationFailureStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@SpringBootTest(properties="spring.datasource.url=jdbc:h2:mem:postfix03a_contract;MODE=MySQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE")
@ActiveProfiles("test")
@Import(SubjectIdentityIsolationRegressionTests.TimeConfig.class)
class SubjectIdentityIsolationRegressionTests {
    static final Instant NOW = Instant.parse("2026-10-16T00:00:00.123456Z");
    @TestConfiguration static class TimeConfig {
        @Bean @Primary Clock identityTestClock() { return Clock.fixed(NOW, ZoneOffset.UTC); }
    }
    @Autowired DeviceTrustLifecycle lifecycle;
    @Autowired TrustedDeviceRegistrationService registration;
    @Autowired KnownDeviceRepository devices;
    @Autowired DeviceRecognitionService recognition;
    @Autowired DeviceFingerprintHasher deviceHasher;
    @Autowired AuthenticationHistoryKeyHasher historyHasher;
    @Autowired JdbcTemplate jdbc;
    @MockitoBean RedisAuthenticationFailureStore redis;

    static Stream<String[]> pairs() {
        String prefix="pf03a-"+UUID.randomUUID();String uuid=UUID.randomUUID().toString();
        return Stream.of(new String[]{prefix+"-case-Case",prefix+"-case-case"}, new String[]{prefix+"-accent-café",prefix+"-accent-cafe"},
                new String[]{prefix+"-form-café",prefix+"-form-cafe\u0301"}, new String[]{"f:"+prefix+":Alice","f:"+prefix+":alice"},
                new String[]{UUID.randomUUID().toString(),UUID.randomUUID().toString()}, new String[]{uuid,uuid.toUpperCase(java.util.Locale.ROOT)});
    }
    private String status(String subject,String device) {
        return recognition.recognize(new LoginContext(subject,"session","Client","192.0.2.3",null,device,NOW)).status().name();
    }
    private long rowsFor(String subject) { return jdbc.queryForObject("SELECT COUNT(*) FROM subject_device_trust WHERE subject_id=?",Long.class,subject); }
    private Map<String,Object> state(String subject) {
        Map<String,Object> result=new LinkedHashMap<>();
        result.put("state",jdbc.queryForList("SELECT * FROM subject_device_trust WHERE subject_id=?",subject));
        result.put("audit",jdbc.queryForList("SELECT * FROM device_trust_revocations WHERE subject_id=?",subject));
        result.put("devices",jdbc.queryForList("SELECT * FROM known_devices WHERE subject_id=?",subject));
        return result;
    }

    @ParameterizedTest @MethodSource("pairs")
    void opaquePairKeepsIndependentGenerationPendingDevicesAndRecognition(String a, String b) {
        String device="device-"+UUID.randomUUID();UUID operation=UUID.randomUUID();
        assertThat(SubjectIdentifierNormalizer.normalize(a)).isNotEqualTo(SubjectIdentifierNormalizer.normalize(b));
        assertThat(deviceHasher.hash(a,device)).isNotEqualTo(deviceHasher.hash(b,device));
        assertThat(historyHasher.hash("subject",a)).isNotEqualTo(historyHasher.hash("subject",b));
        registration.trustAfterMfa(a,device,0);
        assertThat(status(b,device)).isEqualTo("NEW");
        assertThat(devices.findBySubjectIdAndDeviceFingerprintHash(b,deviceHasher.hash(a,device))).isEmpty();
        registration.trustAfterMfa(b,device,0);
        var beforeB=state(b);
        lifecycle.revoke(a,operation,"Admin");
        assertThat(state(b)).isEqualTo(beforeB);
        assertThat(lifecycle.snapshot(b)).isEqualTo(new DeviceTrustLifecycle.Snapshot(0,false));
        assertThat(status(b,device)).isEqualTo("TRUSTED");
        assertThat(devices.findAllBySubjectId(b)).hasSize(1);
        assertThat(rowsFor(a)).isEqualTo(1);assertThat(rowsFor(b)).isEqualTo(1);
        var beforeA=state(a);
        assertThatThrownBy(()->lifecycle.complete(b,operation,"Admin")).isInstanceOf(DeviceTrustRejectedException.class);
        assertThat(state(a)).isEqualTo(beforeA);assertThat(state(b)).isEqualTo(beforeB);
        lifecycle.complete(a,operation,"Admin");lifecycle.complete(a,operation,"Admin");
        assertThat(lifecycle.snapshot(a)).isEqualTo(new DeviceTrustLifecycle.Snapshot(1,false));
    }

    @Test void rejectedCrossOwnerRollsBackNewGenerationRowBeforeAndAfterCompletedReplay() {
        String a="pf03a-"+UUID.randomUUID(),freshB="pf03a-"+UUID.randomUUID();UUID operation=UUID.randomUUID();
        lifecycle.revoke(a,operation,"Admin");var pending=state(a);
        assertThatThrownBy(()->lifecycle.complete(freshB,operation,"Admin")).isInstanceOf(DeviceTrustRejectedException.class);
        assertThat(rowsFor(freshB)).isZero();assertThat(state(a)).isEqualTo(pending);
        lifecycle.complete(a,operation,"Admin");var completed=state(a);
        assertThatThrownBy(()->lifecycle.complete(freshB,operation,"Admin")).isInstanceOf(DeviceTrustRejectedException.class);
        assertThat(rowsFor(freshB)).isZero();assertThat(state(a)).isEqualTo(completed);
        assertThatThrownBy(()->lifecycle.complete(a,operation,"admin")).isInstanceOf(DeviceTrustRejectedException.class);
        assertThat(state(a)).isEqualTo(completed);
        assertThatThrownBy(()->lifecycle.revoke(freshB,operation,"Admin")).isInstanceOf(DeviceTrustRejectedException.class);
        assertThat(rowsFor(freshB)).isZero();assertThat(state(a)).isEqualTo(completed);
    }

    @Test void javaOwnerGuardRejectsSqlAliasEvenWhenAuditWasAlreadyCompleted() {
        JdbcTemplate aliasJdbc=mock(JdbcTemplate.class);KnownDeviceRepository repository=mock(KnownDeviceRepository.class);
        var lifecycle=new DeviceTrustLifecycle(aliasJdbc,repository,Clock.fixed(NOW,ZoneOffset.UTC));
        UUID operation=UUID.randomUUID();String a="f:provider:Alice",b="f:provider:alice";
        when(aliasJdbc.queryForObject(anyString(),eq(Long.class),eq(b))).thenReturn(1L);
        when(aliasJdbc.queryForList(anyString(),any(Object[].class))).thenReturn(java.util.List.of(Map.of("subject_id",a,"requested_by","Admin","completed_at",java.sql.Timestamp.from(NOW))));
        assertThatThrownBy(()->lifecycle.complete(b,operation,"Admin")).isInstanceOf(DeviceTrustRejectedException.class);
        verify(aliasJdbc,never()).update(startsWith("UPDATE"),any(Object[].class));
        verifyNoInteractions(repository);
    }

    @Test void trimIdentityAndTypedUuidRepresentationKeepTheirExistingContracts() {
        String subject="pf03a-"+UUID.randomUUID();UUID operation=UUID.randomUUID();
        assertThat(lifecycle.generation(" "+subject+" ")).isZero();assertThat(rowsFor(subject)).isEqualTo(1);
        assertThat(rowsFor(" "+subject+" ")).isZero();
        assertThat(UUID.fromString(operation.toString().toUpperCase(java.util.Locale.ROOT)).toString()).isEqualTo(operation.toString());
        lifecycle.revoke(subject,operation,"Admin");
        lifecycle.complete(subject,UUID.fromString(operation.toString().toUpperCase(java.util.Locale.ROOT)),"Admin");
        assertThat(lifecycle.snapshot(subject).resetPending()).isFalse();
    }
}
