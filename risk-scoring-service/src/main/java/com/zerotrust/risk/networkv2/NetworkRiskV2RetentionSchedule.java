package com.zerotrust.risk.networkv2;

import org.jboss.logging.Logger;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

@Configuration(proxyBeanMethods = false)
@EnableScheduling
@ConditionalOnProperty(prefix = "risk.network-v2", name = "retention-enabled", havingValue = "true")
public class NetworkRiskV2RetentionSchedule {
    private static final Logger LOG = Logger.getLogger(NetworkRiskV2RetentionSchedule.class);
    private final NetworkRiskV2Retention retention;
    public NetworkRiskV2RetentionSchedule(NetworkRiskV2Retention retention) { this.retention = retention; }
    @Scheduled(fixedDelayString = "${risk.network-v2.retention-interval:PT1H}",
            initialDelayString = "${risk.network-v2.retention-initial-delay:PT10M}")
    public void run() {
        try {
            int count = retention.purgeBatch();
            LOG.infof("ZEROTRUST_NETWORK_V2_RETENTION status=PASS deleted=%d", count);
        } catch (RuntimeException ignored) {
            // No identifiers, SQL exception text, credentials or authentication policy effects.
            LOG.warn("ZEROTRUST_NETWORK_V2_RETENTION status=UNAVAILABLE");
        }
    }
}
