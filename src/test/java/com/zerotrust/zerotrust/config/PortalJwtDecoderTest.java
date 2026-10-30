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

    private String sign(JWTClaimsSet claims) throws JOSEException {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT).keyID(signingKey.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(signingKey));
        return jwt.serialize();
    }
}
