package com.zerotrust.risk.service;

import com.zerotrust.risk.domain.SubjectIdentifierNormalizer;
import com.zerotrust.risk.domain.DeviceTrustTimestamp;
import com.zerotrust.risk.entity.DeviceStatus;
import com.zerotrust.risk.entity.KnownDeviceEntity;
import com.zerotrust.risk.exception.DeviceTrustRejectedException;
import com.zerotrust.risk.repository.DeviceTrustStateRepository;
import com.zerotrust.risk.repository.KnownDeviceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class DeviceTrustLifecycle {
    private final DeviceTrustStateRepository stateRepository;
    private final KnownDeviceRepository devices;
    private final Clock clock;

    @Transactional
    public long generation(String subjectId) {
        subjectId = SubjectIdentifierNormalizer.normalize(subjectId);
        return stateRepository.lockSubject(subjectId).generation();
    }

    public record Snapshot(long generation, boolean resetPending) {}

    @Transactional
    public Snapshot snapshot(String subjectId) {
        subjectId = SubjectIdentifierNormalizer.normalize(subjectId);
        DeviceTrustStateRepository.SubjectState state = stateRepository.lockSubject(subjectId);
        return new Snapshot(state.generation(), state.resetPending());
    }

    // Caller must retain this subject lock until device registration commits.
    @Transactional(propagation = Propagation.MANDATORY)
    public void requireGeneration(String subjectId, long expected) {
        subjectId = SubjectIdentifierNormalizer.normalize(subjectId);
        if (expected < 0) {
            throw new DeviceTrustRejectedException();
        }
        DeviceTrustStateRepository.SubjectState state = stateRepository.lockSubject(subjectId);
        if (state.generation() != expected || state.resetPending()) {
            throw new DeviceTrustRejectedException();
        }
    }

    @Transactional
    public void revoke(String subjectId, UUID operationId, String requestedBy) {
        subjectId = SubjectIdentifierNormalizer.normalize(subjectId);
        DeviceTrustStateRepository.SubjectState state = stateRepository.lockSubject(subjectId);
        var previous = stateRepository.findRevocation(operationId);
        if (previous.isPresent()) {
            requireOwner(previous.get(), subjectId, requestedBy);
            return;
        }
        long next = Math.addExact(state.generation(), 1);
        stateRepository.markPending(subjectId, next, operationId);
        Instant now = DeviceTrustTimestamp.canonical(clock.instant());
        int count = revokeDevices(subjectId, now);
        stateRepository.recordRevocation(operationId, subjectId, requestedBy, next, count, now);
    }

    @Transactional
    public void complete(String subjectId, UUID operationId, String requestedBy) {
        subjectId = SubjectIdentifierNormalizer.normalize(subjectId);
        DeviceTrustStateRepository.SubjectState state = stateRepository.lockSubject(subjectId);
        DeviceTrustStateRepository.Revocation revocation = stateRepository.findRevocation(operationId)
                .orElseThrow(DeviceTrustRejectedException::new);
        requireOwner(revocation, subjectId, requestedBy);
        if (revocation.completed()) {
            return;
        }
        if (!operationId.toString().equals(state.pendingOperationId())) {
            throw new DeviceTrustRejectedException();
        }
        stateRepository.markCompleted(subjectId, operationId, DeviceTrustTimestamp.canonical(clock.instant()));
    }

    private int revokeDevices(String subjectId, Instant revokedAt) {
        int count = 0;
        for (KnownDeviceEntity device : devices.findCurrentForRevocation(subjectId)) {
            if (device.getStatus() != DeviceStatus.REVOKED) {
                device.revokeForMfaReset(revokedAt);
                count++;
            }
        }
        devices.flush();
        return count;
    }

    private void requireOwner(DeviceTrustStateRepository.Revocation revocation, String subjectId, String requestedBy) {
        if (!revocation.belongsTo(subjectId, requestedBy)) {
            throw new DeviceTrustRejectedException();
        }
    }
}
