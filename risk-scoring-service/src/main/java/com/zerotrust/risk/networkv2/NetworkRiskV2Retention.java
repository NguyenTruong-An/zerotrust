package com.zerotrust.risk.networkv2;

import com.zerotrust.risk.config.NetworkRiskV2Properties;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import javax.sql.DataSource;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;

/** Deletes only old shadow context; never parent successes, trust, operations or audit. */
@Service
public class NetworkRiskV2Retention {
    private final JdbcTemplate jdbc;
    private final NetworkRiskV2Properties properties;
    private final Clock clock;
    public NetworkRiskV2Retention(DataSource source, NetworkRiskV2Properties properties, Clock clock) {
        jdbc = new JdbcTemplate(source); jdbc.setQueryTimeout(2);
        this.properties = properties; this.clock = clock;
    }
    @Transactional(timeout = 5)
    public int purgeBatch() {
        if (!properties.isShadow() || !properties.isRetentionEnabled()) return 0;
        Timestamp cutoff = Timestamp.from(clock.instant().minus(Duration.ofDays(properties.getRetentionDays())));
        var ids = jdbc.query("""
                SELECT event_id FROM network_authentication_contexts
                WHERE recorded_at < ? AND authenticated_at < ?
                ORDER BY recorded_at, event_id LIMIT ?
                """, (row, index) -> row.getString(1), cutoff, cutoff, properties.getRetentionBatchSize());
        int deleted = 0;
        for (String id : ids) {
            deleted += jdbc.update("""
                    DELETE FROM network_authentication_contexts
                    WHERE event_id = ? AND recorded_at < ? AND authenticated_at < ?
                    """, id, cutoff, cutoff);
        }
        return deleted;
    }
}
