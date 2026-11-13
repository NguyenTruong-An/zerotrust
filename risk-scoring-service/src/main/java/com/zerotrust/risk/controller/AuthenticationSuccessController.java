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
    private final com.zerotrust.risk.networkv2.NetworkRiskV2Shadow networkRiskV2;

    @PostMapping
    public ResponseEntity<Void> record(@Valid @RequestBody AuthenticationSuccessRequest request) {
        boolean inserted = authenticationSuccessService.recordSuccess(
                request.eventId(),
                request.subjectId(),
                request.clientId(),
                request.authenticatedAt()
        );
        // A redelivery cannot reassign a verified event to a different network or subject.
        if (inserted) networkRiskV2.verifiedSuccess(request);
        return ResponseEntity.noContent().build();
    }
}
