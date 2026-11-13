package com.zerotrust.zerotrust.security;

import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.*;
import java.util.*;

import static org.assertj.core.api.Assertions.*;

class FreshAdminMfaGuardTest {
    private static final Instant NOW = Instant.parse("2026-11-13T00:00:00Z");
    private static final String SUBJECT = "11111111-1111-4111-8111-111111111111";
    private final FreshAdminMfaGuard guard = new FreshAdminMfaGuard(Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofMinutes(5), "zerotrust-spa");

    private Map<String, Object> proof() {
        return new HashMap<>(Map.of("sub", SUBJECT, "azp", "zerotrust-spa", "zt_mfa_subject", SUBJECT,
                "zt_mfa_client", "zerotrust-spa", "zt_mfa_method", "otp", "zt_mfa_at", NOW.getEpochSecond()));
    }
    private JwtAuthenticationToken auth(Map<String, Object> claims, String role) {
        var jwt = Jwt.withTokenValue("offline-fixture-not-a-live-token").header("alg", "RS256")
                .claims(c -> c.putAll(claims)).build();
        return new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_" + role)));
    }
    private void rejects(Map<String, Object> claims) {
        assertThatThrownBy(() -> guard.requireFresh(auth(claims, "ADMIN")))
                .isInstanceOf(WebException.class).extracting(e -> ((WebException)e).getErrorCode())
                .isEqualTo(ErrorCode.FRESH_ADMIN_MFA_REQUIRED);
    }

    @ParameterizedTest @ValueSource(strings={"otp", "recovery-authn-codes"})
    void acceptsOnlySupportedServerFactorMethods(String method) {
        var claims=proof(); claims.put("zt_mfa_method", method);
        assertThatCode(() -> guard.requireFresh(auth(claims,"ADMIN"))).doesNotThrowAnyException();
    }
    @ParameterizedTest @ValueSource(strings={"zt_mfa_at","zt_mfa_method","zt_mfa_subject","zt_mfa_client"})
    void rejectsEveryMissingProofFieldEvenWithNewIatAndAuthTime(String field) {
        var claims=proof(); claims.remove(field);
        claims.put("iat",NOW); claims.put("auth_time",NOW.getEpochSecond()); rejects(claims);
    }
    @Test void refreshIatCannotRenewOldFactor() {
        var claims=proof(); claims.put("zt_mfa_at",NOW.minusSeconds(301).getEpochSecond());
        claims.put("iat",NOW); claims.put("auth_time",NOW.getEpochSecond()); rejects(claims);
    }
    @Test void exactMaximumAgeIsAcceptedButNoFutureFactorIsAccepted() {
        var claims=proof(); claims.put("zt_mfa_at",NOW.minusSeconds(300).getEpochSecond());
        assertThatCode(() -> guard.requireFresh(auth(claims,"ADMIN"))).doesNotThrowAnyException();
        claims.put("zt_mfa_at",NOW.plusSeconds(1).getEpochSecond()); rejects(claims);
    }
    @ParameterizedTest @ValueSource(strings={"password","cookie","CONFIGURE_TOTP"})
    void passwordCookieAndEnrollmentAreNotFactors(String value) {
        var claims=proof(); claims.put("zt_mfa_method",value); rejects(claims);
    }
    @Test void rejectsWrongSubjectOrClientBindings() {
        for (String field:List.of("zt_mfa_subject","zt_mfa_client","azp")) {
            var claims=proof(); claims.put(field,"different"); rejects(claims);
        }
    }
    @Test void rejectsNonCanonicalOrUnboundedTimeWithoutInternalError() {
        for (Object value:List.of("now",1.5,Double.NaN,Long.MAX_VALUE,-1)) {
            var claims=proof(); claims.put("zt_mfa_at",value); rejects(claims);
        }
    }
    @Test void validFactorDoesNotGrantStudentAdminRole() {
        assertThatThrownBy(() -> guard.requireFresh(auth(proof(),"STUDENT")))
                .isInstanceOf(WebException.class).extracting(e -> ((WebException)e).getErrorCode()).isEqualTo(ErrorCode.FORBIDDEN);
    }
    @Test void noAuthenticationIsDenied() {
        assertThatThrownBy(() -> guard.requireFresh(null)).isInstanceOf(WebException.class);
    }
    @Test void cannotConfigureAnUnboundedFreshnessWindow() {
        assertThatThrownBy(() -> new FreshAdminMfaGuard(Clock.systemUTC(),Duration.ofHours(1),"zerotrust-spa"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
