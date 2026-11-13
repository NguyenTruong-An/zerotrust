package com.zerotrust.risk.networkv2;

import com.zerotrust.risk.config.NetworkRiskV2Properties;
import org.junit.jupiter.api.Test;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import static org.assertj.core.api.Assertions.assertThat;

class NetworkRiskV2WorkQueueTests {
    @Test void saturatedWorkerNeverBlocksCallerAndPreservesAcceptedWorkOrder() throws Exception {
        var properties = new NetworkRiskV2Properties(); properties.setWorkQueueCapacity(1);
        var queue = new NetworkRiskV2WorkQueue(properties);
        var entered = new CountDownLatch(1); var release = new CountDownLatch(1); var done = new CountDownLatch(1);
        var order = new ArrayList<Integer>();
        try {
            assertThat(queue.offer(() -> {
                entered.countDown();
                try { release.await(5, TimeUnit.SECONDS); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                order.add(1);
            })).isTrue();
            assertThat(entered.await(2, TimeUnit.SECONDS)).isTrue();
            assertThat(queue.offer(() -> { order.add(2); done.countDown(); })).isTrue();
            assertThat(queue.offer(() -> order.add(3))).isFalse();
            assertThat(queue.droppedCount()).isEqualTo(1);
            release.countDown();
            assertThat(done.await(2, TimeUnit.SECONDS)).isTrue();
            assertThat(order).containsExactly(1, 2);
        } finally { release.countDown(); queue.close(); }
    }
    @Test void rejectedAndFailedTelemetryCannotThrowOnTheAuthenticationThread() throws Exception {
        var queue = new NetworkRiskV2WorkQueue(new NetworkRiskV2Properties());
        var done = new CountDownLatch(1);
        try {
            assertThat(queue.offer(() -> { throw new IllegalStateException("synthetic"); })).isTrue();
            assertThat(queue.offer(done::countDown)).isTrue();
            assertThat(done.await(2, TimeUnit.SECONDS)).isTrue();
        } finally { queue.close(); }
        assertThat(queue.offer(() -> {})).isFalse();
    }
}
