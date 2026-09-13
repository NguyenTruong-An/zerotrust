package com.zerotrust.keycloak.risk.client;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Supplier;

public final class ServiceTokenCache {

    private final ConcurrentMap<TokenCacheKey, CachedToken> tokens = new ConcurrentHashMap<>();

    CachedToken getOrLoad(
            TokenCacheKey key,
            Instant now,
            Duration refreshSkew,
            Supplier<CachedToken> loader
    ) {
        CachedToken existing = tokens.get(key);
        if (isUsable(existing, now, refreshSkew)) {
            return existing;
        }

        return tokens.compute(key, (ignored, current) -> {
            if (isUsable(current, now, refreshSkew)) {
                return current;
            }
            return Objects.requireNonNull(loader.get(), "loader returned no service token");
        });
    }

    void invalidate(TokenCacheKey key, String rejectedToken) {
        tokens.computeIfPresent(key, (ignored, current) ->
                current.accessToken().equals(rejectedToken) ? null : current);
    }

    public void clear() {
        tokens.clear();
    }

    private static boolean isUsable(
            CachedToken token,
            Instant now,
            Duration refreshSkew
    ) {
        return token != null && now.plus(refreshSkew).isBefore(token.expiresAt());
    }

    record TokenCacheKey(URI tokenEndpointUri, String clientId) {
        TokenCacheKey {
            Objects.requireNonNull(tokenEndpointUri, "tokenEndpointUri must not be null");
            Objects.requireNonNull(clientId, "clientId must not be null");
        }
    }

    record CachedToken(String accessToken, Instant expiresAt) {
        CachedToken {
            if (accessToken == null || accessToken.isBlank()) {
                throw new IllegalArgumentException("accessToken must not be blank");
            }
            Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        }
    }
}
