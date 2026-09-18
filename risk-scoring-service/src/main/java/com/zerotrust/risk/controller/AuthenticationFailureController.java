package com.zerotrust.risk.controller;

import com.zerotrust.risk.dto.request.AuthenticationFailureRequest;
import com.zerotrust.risk.service.AuthenticationFailureService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/v1/authentication-failures")
@RequiredArgsConstructor
public class AuthenticationFailureController {

    private final AuthenticationFailureService authenticationFailureService;

    @PostMapping
    public ResponseEntity<Void> record(@Valid @RequestBody AuthenticationFailureRequest request) {
        authenticationFailureService.recordFailure(
                request.eventId(),
                request.subjectId(),
                request.sourceIp()
        );
        return ResponseEntity.noContent().build();
    }
}
