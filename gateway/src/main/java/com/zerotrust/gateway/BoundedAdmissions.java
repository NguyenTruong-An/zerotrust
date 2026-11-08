package com.zerotrust.gateway;

import java.util.*;
import java.util.function.LongSupplier;

/** Single-process, bounded-memory admission. No Redis/Risk counters; no queue or active-key eviction. */
final class BoundedAdmissions {
    private final GatewayEdgePolicy policy;
    private final LongSupplier clock;
    private final Map<String,Bucket> buckets=new HashMap<>();
    private int active;
    private static final class Bucket {
        double tokens;long time,lastUse;int active;
        Bucket(int burst,long now) { tokens=burst;time=lastUse=now; }
    }
    record Admission(Runnable release,int retryAfter) { boolean accepted(){return release!=null;} }
    BoundedAdmissions(GatewayEdgePolicy policy,LongSupplier clock){this.policy=policy;this.clock=clock;}
    synchronized Admission acquire(String key,boolean api) {
        long now=clock.getAsLong();
        buckets.values().removeIf(b->b.active==0 && now-b.lastUse>=policy.idleTtl().toNanos());
        if(active>=policy.maxInFlight())return new Admission(null,1);
        int rate=api?policy.apiRate():policy.staticRate(),burst=api?policy.apiBurst():policy.staticBurst();
        Bucket b=buckets.get(key);
        if(b==null){if(buckets.size()>=policy.maxKeys())return new Admission(null,1);b=new Bucket(burst,now);buckets.put(key,b);}
        b.tokens=Math.min(burst,b.tokens+Math.max(0,now-b.time)/1e9*rate);b.time=b.lastUse=now;
        if(b.active>=(api?policy.subjectConcurrency():policy.staticConcurrency()))return new Admission(null,1);
        if(b.tokens<1)return new Admission(null,Math.max(1,(int)Math.ceil((1-b.tokens)/rate)));
        b.tokens--;b.active++;active++;Bucket admitted=b;
        java.util.concurrent.atomic.AtomicBoolean once=new java.util.concurrent.atomic.AtomicBoolean();
        return new Admission(()->{if(once.compareAndSet(false,true))release(admitted);},0);
    }
    private synchronized void release(Bucket b){b.active--;active--;}
    synchronized int keyCount(){return buckets.size();}
    synchronized int activeCount(){return active;}
}
