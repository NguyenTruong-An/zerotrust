package com.zerotrust.risk.networkv2;

import com.zerotrust.risk.config.NetworkRiskV2Properties;
import org.junit.jupiter.api.Test;
import java.time.*;
import java.util.UUID;
import static org.assertj.core.api.Assertions.assertThat;

class PendingNetworkObservationsTests {
    @Test void correlationIsOneUseAndWrongSubjectOrClientCannotConsumeIt() {
        var now = Instant.parse("2026-11-12T12:00:00Z");
        var cache = new PendingNetworkObservations(new NetworkRiskV2Properties(), Clock.fixed(now, ZoneOffset.UTC));
        var id = UUID.randomUUID();
        var value = new PendingNetworkObservations.Pending("owner", "client", null, now, 1);
        cache.remember(id, value);
        assertThat(cache.consume(id, "other", "client")).isNull();
        assertThat(cache.consume(id, "owner", "other")).isNull();
        assertThat(cache.consume(id, "owner", "client")).isEqualTo(value);
        assertThat(cache.consume(id, "owner", "client")).isNull();
    }
    @Test void capacityAndExpiryBoundUnverifiedAttempts() {
        var now = Instant.parse("2026-11-12T12:00:00Z");
        var properties = new NetworkRiskV2Properties(); properties.setPendingCapacity(1);
        var cache = new PendingNetworkObservations(properties, Clock.fixed(now, ZoneOffset.UTC));
        var first = UUID.randomUUID(); var second = UUID.randomUUID();
        cache.remember(first, new PendingNetworkObservations.Pending("owner", "client", null, now, 0));
        cache.remember(second, new PendingNetworkObservations.Pending("owner", "client", null, now, 0));
        assertThat(cache.consume(first, "owner", "client")).isNull();
        assertThat(cache.consume(second, "owner", "client")).isNotNull();
        cache.remember(first, new PendingNetworkObservations.Pending("owner", "client", null, now.minusSeconds(600), 0));
        assertThat(cache.consume(first, "owner", "client")).isNull();
    }
    @Test void addressScopeRejectsNatAndTransitionRangesWithoutDns() {
        for (String value : java.util.List.of("127.0.0.1", "10.10.1.1", "100.64.1.1", "192.0.2.1", "::1", "fe80::1",
                "2001:db8::1", "64:ff9b::808:808", "2002:808:808::1")) assertThat(NetworkAddressScope.isPublic(value)).isFalse();
        assertThat(NetworkAddressScope.isPublic("8.8.8.8")).isTrue();
        assertThat(NetworkAddressScope.isPublic("2001:4860:4860::8888")).isTrue();
    }
}
