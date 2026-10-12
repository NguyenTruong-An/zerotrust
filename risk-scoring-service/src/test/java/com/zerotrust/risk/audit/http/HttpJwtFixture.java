package com.zerotrust.risk.audit.http;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.*;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Independent, ephemeral RSA signing keys; only the public key is served. Tokens are never logged. */
final class HttpJwtFixture {
    static final String ISSUER = "https://qa01d.invalid/realms/isolated";
    static final String AUD = "zerotrust-risk-api";
    static final String CALLER = "zerotrust-risk-caller";
    static final String ADMIN = "zerotrust-portal-risk-admin";
    static final RSAKey KEY, WRONG;
    static final HttpServer JWKS;
    static final AtomicInteger FETCHES = new AtomicInteger();
    static {
        try {
            KEY = new RSAKeyGenerator(2048).keyID("qa01d").generate();
            WRONG = new RSAKeyGenerator(2048).keyID("qa01d").generate();
            JWKS = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            JWKS.createContext("/jwks", ex -> {
                FETCHES.incrementAndGet();
                byte[] bytes = new JWKSet(KEY.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);
                ex.getResponseHeaders().set("Content-Type", "application/json");
                ex.sendResponseHeaders(200, bytes.length);
                ex.getResponseBody().write(bytes); ex.close();
            });
            JWKS.start();
        } catch (Exception e) { throw new ExceptionInInitializerError(e); }
    }
    static String jwks() { return "http://127.0.0.1:" + JWKS.getAddress().getPort() + "/jwks"; }
    static JWTClaimsSet.Builder claims(String client, String... roles) {
        return new JWTClaimsSet.Builder().issuer(ISSUER).subject("synthetic-service-account")
                .audience(AUD).issueTime(new Date()).expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .claim("azp", client).claim("resource_access", Map.of(AUD, Map.of("roles", List.of(roles))));
    }
    static String sign(JWTClaimsSet.Builder claims, RSAKey key) throws Exception {
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims.build());
        jwt.sign(new RSASSASigner(key)); return jwt.serialize();
    }
    static String token(String client, String... roles) throws Exception { return sign(claims(client, roles), KEY); }
}
