package com.zerotrust.risk.controller;

import com.zerotrust.risk.dto.request.AuthenticationSuccessRequest;
import com.zerotrust.risk.service.AuthenticationSuccessService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/v1/authentication-successes")
@RequiredArgsConstructor
public class AuthenticationSuccessController {

    private final AuthenticationSuccessService authenticationSuccessService;

    @PostMapping
    public ResponseEntity<Void> record(@Valid @RequestBody AuthenticationSuccessRequest request) {
        authenticationSuccessService.recordSuccess(
                request.eventId(),
                request.subjectId(),
                request.clientId(),
                request.authenticatedAt()
        );
        return ResponseEntity.noContent().build();
    }
}
