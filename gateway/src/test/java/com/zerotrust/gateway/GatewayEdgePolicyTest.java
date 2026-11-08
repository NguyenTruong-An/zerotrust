package com.zerotrust.gateway;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import static org.assertj.core.api.Assertions.assertThat;

class GatewayEdgePolicyTest {
    static final String[] VALID={"spring.profiles.active=public-demo","PUBLIC_DEMO_MODE=public-demo",
            "PUBLIC_DEMO_ACADEMIC_READ_ONLY=true","GATEWAY_TRUSTED_PROXY_CIDRS=127.0.0.1/32,2001:db8:1::/64"};
    final ApplicationContextRunner runner=new ApplicationContextRunner()
            .withInitializer(new ConfigDataApplicationContextInitializer()).withUserConfiguration(GatewayEdgePolicy.Wiring.class);
    @Test void publicDemoBindsBoundedEffectivePolicy(){runner.withPropertyValues(VALID).run(c->{
        assertThat(c).hasNotFailed();assertThat(c.getBean(GatewayEdgePolicy.class).enabled()).isTrue();
        assertThat(c.getBean(GatewayEdgePolicy.class).apiBytes()).isEqualTo(65536);
    });}
    @Test void labDefaultsStayUnchanged(){runner.run(c->{assertThat(c).hasNotFailed();assertThat(c.getBean(GatewayEdgePolicy.class).enabled()).isFalse();});}
    @ParameterizedTest @ValueSource(strings={"GATEWAY_TRUSTED_PROXY_CIDRS=","GATEWAY_TRUSTED_PROXY_CIDRS=0.0.0.0/0",
            "GATEWAY_TRUSTED_PROXY_CIDRS=::/0","GATEWAY_TRUSTED_PROXY_CIDRS=proxy.example/32","app.abuse.api-bytes=",
            "app.abuse.api-bytes=0","app.abuse.api-bytes=999999999","app.abuse.api-rate=0","app.abuse.api-burst=-1",
            "app.abuse.body-timeout=PT0S","app.abuse.request-timeout=PT1S","app.abuse.idle-ttl=PT0S",
            "app.abuse.max-in-flight=0","app.abuse.subject-concurrency=100","app.abuse.max-keys=0",
            "server.forward-headers-strategy=framework","server.netty.idle-timeout=PT0S","server.max-http-request-header-size=0",
            "spring.cloud.gateway.server.webflux.httpclient.pool.type=elastic",
            "spring.cloud.gateway.server.webflux.httpclient.pool.max-connections=0",
            "spring.cloud.gateway.server.webflux.httpclient.connect-timeout=0",
            "spring.cloud.gateway.server.webflux.httpclient.response-timeout=PT0S",
            "PUBLIC_DEMO_MODE=lab","PUBLIC_DEMO_ACADEMIC_READ_ONLY=false"})
    void insecureOrMissingEffectiveSettingsFail(String override){runner.withPropertyValues(VALID).withPropertyValues(override).run(c->assertThat(c).hasFailed());}
    @Test void modeAloneCannotSilentlyRunWithoutLimits(){runner.withPropertyValues("PUBLIC_DEMO_MODE=public-demo","PUBLIC_DEMO_ACADEMIC_READ_ONLY=true").run(c->assertThat(c).hasFailed());}
    @Test void prodWithAllMarkersMissingFails(){runner.withPropertyValues("spring.profiles.active=prod").run(c->assertThat(c).hasFailed());}
    @Test void missingMarkerVariablesFail(){runner.withPropertyValues("spring.profiles.active=public-demo").run(c->assertThat(c).hasFailed());}
    @ParameterizedTest @ValueSource(strings={"api-bytes","static-bytes","api-rate","api-burst","static-rate","static-burst",
            "max-in-flight","subject-concurrency","static-concurrency","max-keys","idle-ttl","body-timeout","request-timeout"})
    void anyMissingEffectiveAdmissionLimitFails(String key){runner.withPropertyValues(VALID).withPropertyValues("app.abuse."+key+"=").run(c->assertThat(c).hasFailed());}
    @ParameterizedTest @ValueSource(strings={"server.netty.max-keep-alive-requests=0",
            "spring.cloud.gateway.server.webflux.httpclient.pool.max-idle-time=PT0S",
            "spring.cloud.gateway.server.webflux.httpclient.pool.max-life-time=PT0S",
            "spring.cloud.gateway.server.webflux.httpclient.pool.acquire-timeout=",
            "app.abuse.api-burst=10000","app.abuse.static-concurrency=100"})
    void unsafeLifetimeQueueAndRefillOverridesFail(String value){runner.withPropertyValues(VALID).withPropertyValues(value).run(c->assertThat(c).hasFailed());}
    @Test void oversizedTrustedProxyAllowlistFails(){runner.withPropertyValues(VALID).withPropertyValues(
            "GATEWAY_TRUSTED_PROXY_CIDRS="+String.join(",",java.util.Collections.nCopies(17,"127.0.0.1/32"))).run(c->assertThat(c).hasFailed());}
}
