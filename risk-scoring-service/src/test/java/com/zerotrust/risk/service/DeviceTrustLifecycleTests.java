package com.zerotrust.risk.service;

import com.zerotrust.risk.entity.DeviceStatus;
import com.zerotrust.risk.entity.KnownDeviceEntity;
import com.zerotrust.risk.exception.DeviceTrustRejectedException;
import com.zerotrust.risk.repository.DeviceTrustStateRepository;
import com.zerotrust.risk.repository.KnownDeviceRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.util.AopTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;

@SpringBootTest
@ActiveProfiles("test")
class DeviceTrustLifecycleTests {
    @Autowired DeviceTrustLifecycle lifecycle;
    @Autowired TrustedDeviceRegistrationService registration;
    @Autowired KnownDeviceRepository devices;
    @Autowired DeviceFingerprintHasher hasher;
    @Autowired PlatformTransactionManager transactions;
    @Autowired JdbcTemplate jdbc;
    @MockitoSpyBean DeviceTrustStateRepository stateRepository;

    private final java.util.List<String> subjects = new java.util.ArrayList<>();

    private String newSubject() { String id = UUID.randomUUID().toString(); subjects.add(id); return id; }

    @org.junit.jupiter.api.AfterEach
    void cleanup() {
        for (String subject : subjects) {
            jdbc.update("DELETE FROM known_devices WHERE subject_id = ?", subject);
            jdbc.update("DELETE FROM device_trust_revocations WHERE subject_id = ?", subject);
            jdbc.update("DELETE FROM subject_device_trust WHERE subject_id = ?", subject);
        }
    }

    @Test
    void resetRevokesDevicesAndFencesOldMfaAttemptsEvenWithANewIdentifier() {
        String subject = newSubject();
        UUID operation = UUID.randomUUID();
        long before = lifecycle.generation(subject);
        registration.trustAfterMfa(subject, "old-device", before);
        lifecycle.revoke(subject, operation, "admin-1");
        lifecycle.revoke(subject, operation, "admin-1");
        assertThat(lifecycle.snapshot(subject)).isEqualTo(new DeviceTrustLifecycle.Snapshot(before + 1, true));
        KnownDeviceEntity revoked = devices.findAllBySubjectId(subject).get(0);
        assertThat(revoked.getStatus()).isEqualTo(DeviceStatus.REVOKED);
        assertThat(revoked.getRevocationReason()).isEqualTo("MFA_RESET");
        assertThatThrownBy(() -> registration.trustAfterMfa(subject, "new-device", before + 1))
                .isInstanceOf(DeviceTrustRejectedException.class);
        lifecycle.complete(subject, operation, "admin-1");
        lifecycle.complete(subject, operation, "admin-1");
        assertThatThrownBy(() -> registration.trustAfterMfa(subject, "new-device", before))
                .isInstanceOf(DeviceTrustRejectedException.class);
        assertThatThrownBy(() -> registration.trustAfterMfa(subject, "old-device", before + 1))
                .isInstanceOf(DeviceTrustRejectedException.class);
        registration.trustAfterMfa(subject, "fresh-device", before + 1);
        assertThat(devices.findAllBySubjectId(subject)).hasSize(2);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM device_trust_revocations WHERE operation_id = ?",
                Integer.class, operation.toString())).isEqualTo(1);
    }

    @Test
    void securityRevocationRemainsAHardBlockAndOlderResetCannotCompleteANewerReset() {
        String subject = newSubject();
        KnownDeviceEntity device = new KnownDeviceEntity(subject, hasher.hash(subject, "blocked"), Instant.now().minusSeconds(20));
        device.revoke(Instant.now().minusSeconds(10));
        devices.saveAndFlush(device);
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();
        lifecycle.revoke(subject, first, "admin-1");
        lifecycle.revoke(subject, second, "admin-1");
        assertThatThrownBy(() -> lifecycle.complete(subject, first, "admin-1"))
                .isInstanceOf(DeviceTrustRejectedException.class);
        assertThatThrownBy(() -> lifecycle.complete(subject, second, "other-admin"))
                .isInstanceOf(DeviceTrustRejectedException.class);
        assertThat(devices.findAllBySubjectId(subject).get(0).getRevocationReason()).isEqualTo("SECURITY");
        lifecycle.complete(subject, second, "admin-1");
        assertThat(lifecycle.snapshot(subject).resetPending()).isFalse();
    }

    @Test
    void rejectsOperationReuseByAnotherSubjectOrRequesterWithoutChangingTrustState() {
        String subject = newSubject();
        String otherSubject = newSubject();
        UUID operation = UUID.randomUUID();
        lifecycle.revoke(subject, operation, "admin-1");

        assertThatThrownBy(() -> lifecycle.revoke(otherSubject, operation, "admin-1"))
                .isInstanceOf(DeviceTrustRejectedException.class);
        assertThatThrownBy(() -> lifecycle.revoke(subject, operation, "other-admin"))
                .isInstanceOf(DeviceTrustRejectedException.class);
        assertThatThrownBy(() -> lifecycle.complete(otherSubject, operation, "admin-1"))
                .isInstanceOf(DeviceTrustRejectedException.class);
        assertThat(lifecycle.snapshot(otherSubject)).isEqualTo(new DeviceTrustLifecycle.Snapshot(0, false));
        assertThat(lifecycle.snapshot(subject)).isEqualTo(new DeviceTrustLifecycle.Snapshot(1, true));

        lifecycle.complete(subject, operation, "admin-1");
        assertThat(lifecycle.snapshot(subject)).isEqualTo(new DeviceTrustLifecycle.Snapshot(1, false));
    }

    @Test
    void auditFailureRollsBackGenerationPendingStateAndFlushedDeviceRevocation() {
        String subject = newSubject();
        UUID operation = UUID.randomUUID();
        registration.trustAfterMfa(subject, "trusted-device", 0);
        DeviceTrustStateRepository repositorySpy = AopTestUtils.getUltimateTargetObject(stateRepository);
        doThrow(new DataAccessResourceFailureException("audit write unavailable"))
                .when(repositorySpy).recordRevocation(eq(operation), eq(subject), eq("admin-1"),
                        eq(1L), eq(1), any(Instant.class));

        assertThatThrownBy(() -> lifecycle.revoke(subject, operation, "admin-1"))
                .isInstanceOf(DataAccessResourceFailureException.class);

        assertThat(lifecycle.snapshot(subject)).isEqualTo(new DeviceTrustLifecycle.Snapshot(0, false));
        assertThat(devices.findAllBySubjectId(subject)).singleElement().satisfies(device -> {
            assertThat(device.getStatus()).isEqualTo(DeviceStatus.TRUSTED);
            assertThat(device.getRevokedAt()).isNull();
            assertThat(device.getRevocationReason()).isNull();
        });
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM device_trust_revocations WHERE operation_id = ?",
                Integer.class, operation.toString())).isZero();
    }

    @Test
    void revokeWaitsForInFlightRegistrationTransactionAndThenRevokesItsDevice() throws Exception {
        String subject = newSubject();
        long generation = lifecycle.generation(subject);
        CountDownLatch registered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<?> inFlight = pool.submit(() -> new TransactionTemplate(transactions).executeWithoutResult(status -> {
                registration.trustAfterMfa(subject, "in-flight-device", generation);
                registered.countDown();
                try {
                    if (!release.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("Timed out");
                } catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
            }));
            assertThat(registered.await(5, TimeUnit.SECONDS)).isTrue();
            Future<?> revocation = pool.submit(() -> lifecycle.revoke(subject, UUID.randomUUID(), "admin-1"));
            release.countDown();
            inFlight.get(10, TimeUnit.SECONDS);
            revocation.get(10, TimeUnit.SECONDS);
            assertThat(devices.findAllBySubjectId(subject)).singleElement()
                    .extracting(KnownDeviceEntity::getStatus).isEqualTo(DeviceStatus.REVOKED);
        } finally { release.countDown(); pool.shutdownNow(); }
    }
}
