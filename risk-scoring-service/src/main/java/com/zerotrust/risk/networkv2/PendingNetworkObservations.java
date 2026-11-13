package com.zerotrust.risk.networkv2;

import com.zerotrust.risk.config.NetworkRiskV2Properties;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/** Bounded, expiring, one-use correlation cache. Evaluations here are NOT trusted history. */
@Component
public class PendingNetworkObservations {
    public record Pending(String subjectHash, String clientId, NetworkObservation observation,
                          Instant observedAt, long generation) {}
    private final Map<UUID, Pending> entries = new LinkedHashMap<>();
    private final NetworkRiskV2Properties properties;
    private final Clock clock;
    public PendingNetworkObservations(NetworkRiskV2Properties properties, Clock clock) {
        this.properties = properties; this.clock = clock;
    }
    public synchronized void remember(UUID id, Pending value) {
        expire();
        if (entries.size() >= properties.getPendingCapacity()) entries.remove(entries.keySet().iterator().next());
        entries.put(id, value);
    }
    public synchronized Pending consume(UUID id, String subjectHash, String clientId) {
        expire();
        Pending found = entries.get(id);
        if (found == null || !subjectHash.equals(found.subjectHash()) || !clientId.equals(found.clientId())) return null;
        entries.remove(id);
        return found;
    }
    private void expire() {
        Instant cutoff = clock.instant().minus(properties.getPendingTtl());
        Iterator<Pending> values = entries.values().iterator();
        while (values.hasNext()) if (!values.next().observedAt().isAfter(cutoff)) values.remove();
    }
}
