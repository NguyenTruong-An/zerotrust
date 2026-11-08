import com.zerotrust.risk.config.RiskPolicyProperties;
import com.zerotrust.risk.domain.RiskFactors;
import com.zerotrust.risk.service.RiskScoringService;
import java.math.BigDecimal;
import java.lang.management.ManagementFactory;
import java.util.*;
import java.util.concurrent.*;

/** In-process B0 scoring ONLY. Not HTTP evaluation, feature I/O, login, capacity or SLO proof. */
public class ScoringMicrobenchmark {
    static volatile Object sink;
    public static void main(String[] args) throws Exception {
        var policy = new RiskPolicyProperties();
        var w = policy.getWeights(); var q = new BigDecimal("0.25");
        w.setDevice(q); w.setNetwork(q); w.setTemporal(q); w.setAuthenticationHistory(q);
        policy.getThresholds().setMediumMinimum(new BigDecimal("40"));
        policy.getThresholds().setHighMinimum(new BigDecimal("75"));
        var service = new RiskScoringService(policy);
        var factors = new RiskFactors(BigDecimal.ZERO, new BigDecimal("50"), BigDecimal.ZERO, BigDecimal.ZERO);
        for (int i=0;i<100000;i++) sink=service.evaluate(factors);
        for (int concurrency : new int[]{1,4}) {
            int total=1000000, perThread=total/concurrency;
            var startGate=new CountDownLatch(1);
            var pool=Executors.newFixedThreadPool(concurrency);
            var tasks=new ArrayList<Future<long[]>>();
            long gcBefore=ManagementFactory.getGarbageCollectorMXBeans().stream().mapToLong(b->Math.max(0,b.getCollectionTime())).sum();
            var os=(com.sun.management.OperatingSystemMXBean)ManagementFactory.getOperatingSystemMXBean();
            long cpuBefore=os.getProcessCpuTime();
            for(int t=0;t<concurrency;t++) tasks.add(pool.submit(()->{
                startGate.await(); var durations=new long[perThread];
                for(int i=0;i<perThread;i++) {
                    long began=System.nanoTime(); var result=service.evaluate(factors);
                    durations[i]=System.nanoTime()-began;
                    if(result.riskScore().compareTo(new BigDecimal("12.50"))!=0) throw new AssertionError();
                    sink=result;
                }
                return durations;
            }));
            long began=System.nanoTime();startGate.countDown();
            var all=new long[total];int offset=0;
            for(var task:tasks){var values=task.get(60,TimeUnit.SECONDS);System.arraycopy(values,0,all,offset,values.length);offset+=values.length;}
            long elapsed=System.nanoTime()-began,cpu=os.getProcessCpuTime()-cpuBefore;
            pool.shutdown();pool.awaitTermination(10,TimeUnit.SECONDS);Arrays.sort(all);
            long gcAfter=ManagementFactory.getGarbageCollectorMXBeans().stream().mapToLong(b->Math.max(0,b.getCollectionTime())).sum();
            var heap=ManagementFactory.getMemoryMXBean().getHeapMemoryUsage();
            System.out.printf(Locale.ROOT,"{\"concurrency\":%d,\"operations\":%d,\"duration_ms\":%.3f,\"p50_us\":%.3f,\"p95_us\":%.3f,\"p99_us\":%.3f,\"errors\":0,\"cpu_time_ms\":%.3f,\"average_cpu_cores\":%.3f,\"heap_used_bytes\":%d,\"heap_max_bytes\":%d,\"gc_time_ms\":%d}%n",
                    concurrency,total,elapsed/1e6,all[total/2]/1e3,all[(int)(total*.95)]/1e3,all[(int)(total*.99)]/1e3,cpu/1e6,(double)cpu/elapsed,heap.getUsed(),heap.getMax(),gcAfter-gcBefore);
        }
    }
}
