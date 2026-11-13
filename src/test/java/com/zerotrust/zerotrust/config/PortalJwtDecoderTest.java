package com.zerotrust.zerotrust.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.JwtException;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PortalJwtDecoderTest {
    private static final String ISSUER = "https://issuer.example.invalid/realms/test";
    private static final String AUDIENCE = "zerotrust-api";
    private static final String SUBJECT = "00000000-0000-4000-8000-000000000001";
    private static HttpServer server;
    private static RSAKey signingKey;

    private JwtDecoder decoder;

    @BeforeAll
    static void startJwksServer() throws JOSEException, IOException {
        signingKey = new RSAKeyGenerator(2048).keyID("portal-test-key").generate();
        byte[] jwks = new JWKSet(signingKey.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/jwks", exchange -> {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, jwks.length);
            try (var body = exchange.getResponseBody()) {
                body.write(jwks);
            }
        });
        server.start();
    }

    @AfterAll
    static void stopJwksServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @BeforeEach
    void createProductionDecoder() {
        decoder = new SecurityConfig().jwtDecoder(
                ISSUER, "http://127.0.0.1:" + server.getAddress().getPort() + "/jwks", AUDIENCE);
    }

    @Test
    void rejectsSignedTokenWithoutExpiration() throws JOSEException {
        String token = sign(claims().build());

        assertThatThrownBy(() -> decoder.decode(token))
                .isInstanceOf(JwtValidationException.class);
    }

    @Test
    void rejectsExpiredSignedTokenBeyondClockSkew() throws JOSEException {
        String token = sign(claims().expirationTime(Date.from(Instant.now().minusSeconds(300))).build());

        assertThatThrownBy(() -> decoder.decode(token))
                .isInstanceOf(JwtValidationException.class);
    }

    @Test
    void acceptsSignedTokenWithValidExpiration() throws JOSEException {
        Instant expiration = Instant.now().plusSeconds(300);
        String token = sign(claims().expirationTime(Date.from(expiration)).build());

        var jwt = decoder.decode(token);

        assertThat(jwt.getSubject()).isEqualTo(SUBJECT);
        assertThat(jwt.getExpiresAt()).isEqualTo(Instant.ofEpochSecond(expiration.getEpochSecond()));
    }

    @Test
    void stillRejectsWrongIssuer() throws JOSEException {
        String token = sign(claims().issuer("https://other.example.invalid")
                .expirationTime(Date.from(Instant.now().plusSeconds(300))).build());

        assertThatThrownBy(() -> decoder.decode(token))
                .isInstanceOf(JwtValidationException.class);
    }

    @Test
    void stillRejectsWrongAudience() throws JOSEException {
        String token = sign(claims().audience("account")
                .expirationTime(Date.from(Instant.now().plusSeconds(300))).build());

        assertThatThrownBy(() -> decoder.decode(token))
                .isInstanceOf(JwtValidationException.class);
    }

    @Test
    void stillRejectsTokenNotYetValid() throws JOSEException {
        String token = sign(claims().notBeforeTime(Date.from(Instant.now().plusSeconds(300)))
                .expirationTime(Date.from(Instant.now().plusSeconds(600))).build());

        assertThatThrownBy(() -> decoder.decode(token))
                .isInstanceOf(JwtValidationException.class);
    }

    private JWTClaimsSet.Builder claims() {
        return new JWTClaimsSet.Builder().issuer(ISSUER).subject(SUBJECT).audience(AUDIENCE)
                .issueTime(Date.from(Instant.now().minusSeconds(600)));
    }

    @Test
    void rejectsDifferentSigningKeyEvenWhenTheKeyIdMatches() throws JOSEException {
        // Isolated loopback JWKS fixture; this token is never sent to the canonical runtime.
        RSAKey otherKey = new RSAKeyGenerator(2048).keyID(signingKey.getKeyID()).generate();
        SignedJWT forged = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(signingKey.getKeyID()).build(),
                claims().expirationTime(Date.from(Instant.now().plusSeconds(300))).build());
        forged.sign(new RSASSASigner(otherKey));

        assertThatThrownBy(() -> decoder.decode(forged.serialize())).isInstanceOf(JwtException.class);
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({"-1,true", "59,true", "60,true", "61,false"})
    void actualTimestampValidatorEnforcesExpirySkewBoundary(long secondsAfterExpiry, boolean accepted) {
        Instant expires = Instant.parse("2026-11-13T00:00:00Z");
        var validator = new org.springframework.security.oauth2.jwt.JwtTimestampValidator();
        validator.setClock(java.time.Clock.fixed(expires.plusSeconds(secondsAfterExpiry), java.time.ZoneOffset.UTC));
        var token = org.springframework.security.oauth2.jwt.Jwt.withTokenValue("offline-boundary-fixture")
                .header("alg", "RS256").subject(SUBJECT).expiresAt(expires).build();
        assertThat(validator.validate(token).hasErrors()).isEqualTo(!accepted);
    }

    private JWTClaimsSet.Builder factorClaims(Instant factorAt) {
        Instant now=Instant.now();
        return claims().issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(300)))
                .claim("realm_access", java.util.Map.of("roles",java.util.List.of("ADMIN")))
                .claim("azp","zerotrust-spa").claim("zt_mfa_client","zerotrust-spa")
                .claim("zt_mfa_subject",SUBJECT).claim("zt_mfa_method","otp")
                .claim("zt_mfa_at",factorAt.getEpochSecond());
    }

    @Test void signedFactorProofPassesActualDecoderRoleConverterAndFreshnessGuard() throws JOSEException {
        Instant now=Instant.now();
        var signed=factorClaims(now).expirationTime(Date.from(now.plusSeconds(300))).build();
        var jwt=decoder.decode(sign(signed));
        var auth=new com.zerotrust.zerotrust.security.KeycloakJwtAuthenticationConverter().convert(jwt);
        var guard=new com.zerotrust.zerotrust.security.FreshAdminMfaGuard(
                java.time.Clock.fixed(now,java.time.ZoneOffset.UTC),java.time.Duration.ofMinutes(5),"zerotrust-spa");
        assertThatCode(() -> guard.requireFresh(auth)).doesNotThrowAnyException();
    }

    @Test void newlyIssuedSignedJwtCannotRenewAnOldFactor() throws JOSEException {
        Instant now=Instant.now();
        var signed=factorClaims(now.minusSeconds(301)).issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300))).build();
        var auth=new com.zerotrust.zerotrust.security.KeycloakJwtAuthenticationConverter().convert(decoder.decode(sign(signed)));
        var guard=new com.zerotrust.zerotrust.security.FreshAdminMfaGuard(
                java.time.Clock.fixed(now,java.time.ZoneOffset.UTC),java.time.Duration.ofMinutes(5),"zerotrust-spa");
        assertThatThrownBy(() -> guard.requireFresh(auth)).isInstanceOf(com.zerotrust.zerotrust.exception.WebException.class);
    }

    @Test void changingFactorTimeWithoutTheIssuerSignatureIsRejected() throws JOSEException {
        Instant now=Instant.now();
        String original=sign(factorClaims(now.minusSeconds(301)).expirationTime(Date.from(now.plusSeconds(300))).build());
        String[] parts=original.split("\\.");
        String replacement=com.nimbusds.jose.util.Base64URL.encode(factorClaims(now).expirationTime(Date.from(now.plusSeconds(300))).build().toString()).toString();
        assertThatThrownBy(() -> decoder.decode(parts[0]+"."+replacement+"."+parts[2])).isInstanceOf(JwtException.class);
    }

    private String sign(JWTClaimsSet claims) throws JOSEException {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT).keyID(signingKey.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(signingKey));
        return jwt.serialize();
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"RS384", "RS512", "PS256", "HS256"})
    void rejectsUnsupportedAlgorithmsEvenWithTheTrustedSigningKey(String algorithm) throws JOSEException {
        SignedJWT token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.parse(algorithm))
                .keyID(signingKey.getKeyID()).build(),
                claims().expirationTime(Date.from(Instant.now().plusSeconds(300))).build());
        if (algorithm.equals("HS256")) token.sign(new com.nimbusds.jose.crypto.MACSigner(new byte[32]));
        else token.sign(new RSASSASigner(signingKey));
        assertThatThrownBy(() -> decoder.decode(token.serialize())).isInstanceOf(JwtException.class);
    }

    @Test void unsignedTokenCannotUseTheTrustedIssuerAndAudience() {
        var token = new com.nimbusds.jwt.PlainJWT(claims().expirationTime(Date.from(Instant.now().plusSeconds(300))).build());
        assertThatThrownBy(() -> decoder.decode(token.serialize())).isInstanceOf(JwtException.class);
    }
}
