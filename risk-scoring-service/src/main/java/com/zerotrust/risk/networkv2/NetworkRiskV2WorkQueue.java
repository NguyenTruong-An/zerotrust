package com.zerotrust.risk.networkv2;

import com.zerotrust.risk.config.NetworkRiskV2Properties;
import jakarta.annotation.PreDestroy;
import org.springframework.stereotype.Component;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.LongAdder;

/** A single FIFO worker preserves evaluation-before-success ordering without blocking login. */
@Component
public class NetworkRiskV2WorkQueue implements io.micrometer.core.instrument.binder.MeterBinder {
    private final ThreadPoolExecutor executor;
    private final LongAdder dropped = new LongAdder();
    public NetworkRiskV2WorkQueue(NetworkRiskV2Properties properties) {
        executor = new ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(properties.getWorkQueueCapacity()), runnable -> {
                    Thread thread = new Thread(runnable, "network-v2-shadow"); thread.setDaemon(true); return thread;
                }, new ThreadPoolExecutor.AbortPolicy());
    }
    public boolean offer(Runnable observation) {
        try {
            executor.execute(() -> {
                try { observation.run(); } catch (RuntimeException | LinkageError ignored) { /* Shadow only. */ }
            });
            return true;
        } catch (RejectedExecutionException unavailable) {
            dropped.increment();
            return false; // Never CallerRunsPolicy: no network-history work on an authentication thread.
        }
    }
    public long droppedCount() { return dropped.sum(); }
    public int queueDepth() { return executor.getQueue().size(); }
    @Override public void bindTo(io.micrometer.core.instrument.MeterRegistry registry) {
        io.micrometer.core.instrument.FunctionCounter.builder("risk.network.v2.shadow.dropped", this,
                queue -> (double) queue.droppedCount()).register(registry);
        registry.gauge("risk.network.v2.shadow.queue.depth", this, queue -> (double) queue.queueDepth());
    }
    @PreDestroy public void close() { executor.shutdownNow(); }
}
