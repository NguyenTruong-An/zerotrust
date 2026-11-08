package com.zerotrust.gateway;

import org.junit.jupiter.api.Test;
import java.util.concurrent.atomic.AtomicLong;
import static org.junit.jupiter.api.Assertions.*;

class BoundedAdmissionsTest {
    @Test void burstRefillAndSameNatSubjectsAreIndependent(){
        AtomicLong time=new AtomicLong();var limits=new BoundedAdmissions(GatewayCanonicalIpTest.policy(),time::get);
        for(int i=0;i<3;i++){var a=limits.acquire("subject-A",true);assertTrue(a.accepted());a.release().run();}
        assertFalse(limits.acquire("subject-A",true).accepted());assertEquals(1,limits.acquire("subject-A",true).retryAfter());
        var b=limits.acquire("subject-B",true);assertTrue(b.accepted());b.release().run();
        time.set(1_000_000_000L);var again=limits.acquire("subject-A",true);assertTrue(again.accepted());again.release().run();
    }
    @Test void concurrencyAndReleaseAreBoundedAndIdempotent(){
        var limits=new BoundedAdmissions(GatewayCanonicalIpTest.policy(),()->0);
        var one=limits.acquire("A",true);var two=limits.acquire("A",true);
        assertFalse(limits.acquire("A",true).accepted());
        var three=limits.acquire("B",true);var four=limits.acquire("B",true);
        assertFalse(limits.acquire("C",true).accepted());
        one.release().run();one.release().run();two.release().run();three.release().run();four.release().run();assertEquals(0,limits.activeCount());
    }
    @Test void activeMemoryTableDoesNotEvictKeysToBypassLimits(){
        AtomicLong time=new AtomicLong();var limits=new BoundedAdmissions(GatewayCanonicalIpTest.policy(),time::get);
        for(int i=0;i<16;i++){var a=limits.acquire("subject"+i,true);assertTrue(a.accepted());a.release().run();}
        assertEquals(16,limits.keyCount());assertFalse(limits.acquire("new-subject",true).accepted());
        time.set(61_000_000_000L);var a=limits.acquire("new-subject",true);assertTrue(a.accepted());a.release().run();assertEquals(1,limits.keyCount());
    }
}
