package com.zerotrust.zerotrust.security;

import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

/** Consumes server-recorded native-factor claims only after the resource server validates JWT. */
@Component
public final class FreshAdminMfaGuard {
    private final Clock clock;
    private final Duration maximumAge;
    private final String clientId;

    @Autowired
    public FreshAdminMfaGuard(
            @Value("${app.security.fresh-admin-mfa.maximum-age-seconds:300}") long maximumAgeSeconds,
            @Value("${app.security.fresh-admin-mfa.client-id:zerotrust-spa}") String clientId) {
        this(Clock.systemUTC(), Duration.ofSeconds(maximumAgeSeconds), clientId);
    }

    public FreshAdminMfaGuard(Clock clock, Duration maximumAge, String clientId) {
        if (clock == null || maximumAge == null || maximumAge.isNegative() || maximumAge.isZero()
                || maximumAge.compareTo(Duration.ofMinutes(5)) > 0 || clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("Invalid fresh ADMIN MFA configuration");
        }
        this.clock = clock;
        this.maximumAge = maximumAge;
        this.clientId = clientId;
    }

    public void requireFresh(Authentication authentication) {
        if (!(authentication instanceof JwtAuthenticationToken token) || !token.isAuthenticated()
                || token.getAuthorities().stream().noneMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()))) {
            throw new WebException(ErrorCode.FORBIDDEN);
        }
        var jwt = token.getToken();
        Object subject = jwt.getClaims().get("sub");
        Object method = jwt.getClaims().get("zt_mfa_method");
        Object at = jwt.getClaims().get("zt_mfa_at");
        if (!(subject instanceof String s) || s.isBlank()
                || !s.equals(jwt.getClaims().get("zt_mfa_subject"))
                || !clientId.equals(jwt.getClaims().get("azp"))
                || !clientId.equals(jwt.getClaims().get("zt_mfa_client"))
                || !(method instanceof String m) || !Set.of("otp", "recovery-authn-codes").contains(m)
                || !(at instanceof Number number)) {
            throw required();
        }
        try {
            long seconds = new BigDecimal(number.toString()).longValueExact();
            Instant factorAt = Instant.ofEpochSecond(seconds);
            Instant now = clock.instant();
            if (seconds <= 0 || factorAt.isAfter(now)
                    || Duration.between(factorAt, now).compareTo(maximumAge) > 0) throw required();
        } catch (ArithmeticException | java.time.DateTimeException | NumberFormatException exception) {
            throw required();
        }
        // iat/auth_time, browser cookies and request timestamps are deliberately not used.
    }

    private WebException required() {
        return new WebException(ErrorCode.FRESH_ADMIN_MFA_REQUIRED);
    }
    public String requireReset(Authentication authentication,String targetSubject) {
        requireFresh(authentication);
        var jwt=((JwtAuthenticationToken)authentication).getToken();
        if(!targetSubject.equals(jwt.getClaims().get("zt_mfa_target")) || !"MFA_RESET".equals(jwt.getClaims().get("zt_mfa_action"))
                || jwt.getClaimAsString("sid")==null || !jwt.getClaimAsString("sid").equals(jwt.getClaims().get("zt_mfa_sid"))
                || !(jwt.getClaims().get("zt_mfa_attempt") instanceof String attempt) || attempt.isBlank())throw required();
        try{return java.util.UUID.fromString(jwt.getClaimAsString("zt_mfa_proof")).toString();}
        catch(RuntimeException failure){throw required();}
    }
}
