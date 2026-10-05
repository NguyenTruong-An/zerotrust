package com.zerotrust.risk.controller;

import com.zerotrust.risk.service.DeviceTrustLifecycle;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequiredArgsConstructor
public class TrustedDeviceRevocationController {
    private final DeviceTrustLifecycle lifecycle;

    @PostMapping("/internal/v1/subjects/{subjectId}/trusted-devices/revocations")
    public ResponseEntity<Void> revoke(@PathVariable UUID subjectId, @Valid @RequestBody RevocationRequest request) {
        lifecycle.revoke(subjectId.toString(), request.operationId(), request.requestedBy());
        return ResponseEntity.noContent().build();
    }

    public record RevocationRequest(@NotNull UUID operationId,
                                    @NotBlank @Size(max = 255) String requestedBy) {}

    @PostMapping("/internal/v1/subjects/{subjectId}/trusted-devices/revocations/completion")
    public ResponseEntity<Void> complete(@PathVariable UUID subjectId, @Valid @RequestBody RevocationRequest request) {
        lifecycle.complete(subjectId.toString(), request.operationId(), request.requestedBy());
        return ResponseEntity.noContent().build();
    }
}
