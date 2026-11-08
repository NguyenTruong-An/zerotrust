package com.zerotrust.gateway;

import org.springframework.context.annotation.*;
import org.springframework.core.env.Environment;
import java.time.Duration;
import java.util.*;

/** PROPOSED bounded test defaults live in the public-demo profile; missing effective settings fail. */
record GatewayEdgePolicy(boolean enabled, List<ClientIp.Cidr> proxies, int apiBytes, int staticBytes,
                         int apiRate, int apiBurst, int staticRate, int staticBurst, int maxInFlight,
                         int subjectConcurrency, int staticConcurrency, int maxKeys, Duration idleTtl,
                         Duration bodyTimeout, Duration requestTimeout) {
    static GatewayEdgePolicy disabled() {
        return new GatewayEdgePolicy(false,List.of(),0,0,0,0,0,0,0,0,0,0,Duration.ZERO,Duration.ZERO,Duration.ZERO);
    }
    static GatewayEdgePolicy bind(Environment env) {
        try {
            String mode=env.getProperty("app.public-demo.mode","lab");
            String flag=env.getProperty("app.public-demo.academic-read-only","");
            boolean prod=Arrays.stream(env.getActiveProfiles()).anyMatch(p->Set.of("prod","production","public-demo").contains(p));
            if (!prod && mode.equals("lab") && flag.isBlank()) return disabled();
            check(mode.equals("public-demo") && flag.equals("true"));
            check("none".equals(env.getProperty("server.forward-headers-strategy")));
            List<ClientIp.Cidr> proxies=Arrays.stream(required(env,"app.abuse.trusted-proxies").split(",",-1))
                    .map(String::trim).map(ClientIp.Cidr::parse).toList();
            check(proxies.size()<=16);
            int rate=number(env,"api-rate",1,10000),burst=number(env,"api-burst",1,10000);
            int sr=number(env,"static-rate",1,10000),sb=number(env,"static-burst",1,10000);
            int all=number(env,"max-in-flight",1,256),per=number(env,"subject-concurrency",1,256),sp=number(env,"static-concurrency",1,256);
            check(per<=all && sp<=all);
            Duration ttl=duration(env,"idle-ttl",1,600),body=duration(env,"body-timeout",1,30),total=duration(env,"request-timeout",1,60);
            check(total.compareTo(body)>0 && ttl.toNanos()>=Math.max((long)Math.ceil((double)burst/rate*1e9),(long)Math.ceil((double)sb/sr*1e9)));
            numberRaw(env,"server.max-http-request-header-size",4096,65536);
            durationRaw(env,"server.netty.idle-timeout",1,60);
            numberRaw(env,"server.netty.max-keep-alive-requests",1,1000);
            int connect=numberRaw(env,"spring.cloud.gateway.server.webflux.httpclient.connect-timeout",1,10000);
            check(connect>0);
            durationRaw(env,"spring.cloud.gateway.server.webflux.httpclient.response-timeout",1,30);
            check("fixed".equals(required(env,"spring.cloud.gateway.server.webflux.httpclient.pool.type")));
            numberRaw(env,"spring.cloud.gateway.server.webflux.httpclient.pool.max-connections",1,256);
            numberRaw(env,"spring.cloud.gateway.server.webflux.httpclient.pool.acquire-timeout",1,10000);
            durationRaw(env,"spring.cloud.gateway.server.webflux.httpclient.pool.max-idle-time",1,60);
            durationRaw(env,"spring.cloud.gateway.server.webflux.httpclient.pool.max-life-time",1,300);
            return new GatewayEdgePolicy(true,proxies,number(env,"api-bytes",1,1048576),number(env,"static-bytes",1,1048576),
                    rate,burst,sr,sb,all,per,sp,number(env,"max-keys",16,65536),ttl,body,total);
        } catch (RuntimeException ignored) {
            throw new IllegalStateException("Public Demo Gateway configuration rejected (values redacted)");
        }
    }
    private static void check(boolean condition) { if (!condition) throw new IllegalArgumentException(); }
    private static String required(Environment e,String key) {
        String s=e.getProperty(key); check(s!=null && !s.isBlank() && !s.contains("${"));return s;
    }
    private static int number(Environment e,String key,int min,int max) { return numberRaw(e,"app.abuse."+key,min,max); }
    private static int numberRaw(Environment e,String key,int min,int max) {
        int value=Integer.parseInt(required(e,key));check(value>=min && value<=max);return value;
    }
    private static Duration duration(Environment e,String key,int min,int max) { return durationRaw(e,"app.abuse."+key,min,max); }
    private static Duration durationRaw(Environment e,String key,int min,int max) {
        Duration d=Duration.parse(required(e,key));check(d.compareTo(Duration.ofSeconds(min))>=0 && d.compareTo(Duration.ofSeconds(max))<=0);return d;
    }

    @Configuration(proxyBeanMethods=false)
    static class Wiring {
        @Bean GatewayEdgePolicy gatewayEdgePolicy(Environment environment) { return bind(environment); }
        @Bean java.util.function.LongSupplier gatewayAdmissionClock() { return System::nanoTime; }
    }
}
