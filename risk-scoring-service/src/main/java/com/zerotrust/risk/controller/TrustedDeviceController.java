package com.zerotrust.risk.controller;

import com.zerotrust.risk.dto.request.TrustedDeviceRegistrationRequest;
import com.zerotrust.risk.service.TrustedDeviceRegistrationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/v1/trusted-devices")
@RequiredArgsConstructor
public class TrustedDeviceController {

    private final TrustedDeviceRegistrationService registrationService;

    @PostMapping
    public ResponseEntity<Void> register(@Valid @RequestBody TrustedDeviceRegistrationRequest request) {
        registrationService.trustAfterMfa(request.subjectId(), request.deviceId());
        return ResponseEntity.noContent().build();
    }
}
