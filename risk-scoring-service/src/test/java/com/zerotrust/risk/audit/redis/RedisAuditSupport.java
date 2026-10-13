package com.zerotrust.risk.audit.redis;

import com.zerotrust.risk.config.AuthenticationHistoryProperties;
import com.zerotrust.risk.config.AuthenticationHistoryRiskProperties;
import com.zerotrust.risk.repository.RedisAuthenticationFailureStore;
import com.zerotrust.risk.service.AuthenticationHistoryKeyHasher;
import io.lettuce.core.ClientOptions;
import io.lettuce.core.SocketOptions;
import io.lettuce.core.protocol.ProtocolVersion;
import io.lettuce.core.resource.DefaultClientResources;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInfo;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/** Opt-in concrete classes only. No Spring Boot context, application profiles or environment endpoint. */
abstract class RedisAuditSupport {
    static final String HOST = "127.0.0.1";
    static final int QA_PORT = 6380;
    static final String PEPPER = "qa01c2-only-synthetic-auth-history-pepper";
    static final String RUN = UUID.randomUUID().toString().replace("-", "");
    final List<Client> clients = new ArrayList<>();
    final Set<String> observedKeys = new LinkedHashSet<>();
    DefaultClientResources resources;
    AuthenticationHistoryProperties properties;
    Client primary;
    String scenario;
    Properties commandsBefore;

    @BeforeEach
    void prepare(TestInfo info) {
        if (!"true".equals(System.getProperty("qa.redis.audit"))) throw new IllegalStateException("Redis audit opt-in missing");
        if (System.getProperty("qa.redis.runId", "").isBlank()) throw new IllegalStateException("Preflight run ID required");
        scenario = info.getDisplayName();
        properties = new AuthenticationHistoryProperties();
        properties.setPepper(PEPPER);
        properties.setKeyPrefix("qa01c2:fix05:" + RUN + ":" + UUID.randomUUID().toString().replace("-", ""));
        properties.setFailureWindow(Duration.ofSeconds(60));
        properties.setEventDeduplicationTtl(Duration.ofSeconds(120));
        resources = DefaultClientResources.builder().ioThreadPoolSize(2).computationThreadPoolSize(2).build();
        primary = client(QA_PORT, Duration.ofSeconds(2));
        commandsBefore = primary.template.execute((RedisCallback<Properties>) c -> c.serverCommands().info("commandstats"));
        evidence("IDENTITY version=7.4.7 endpoint=" + HOST + ':' + QA_PORT + " db=0 clientId=" + primary.id() + " namespace=" + properties.getKeyPrefix() + " productionLuaSha1=" + scriptSha1());
    }

    Client client() { return client(QA_PORT, Duration.ofSeconds(2)); }

    // Proxy ports are test-owned loopback listeners; their upstream is exclusively QA_PORT.
    Client client(int port, Duration timeout) {
        return client(port, timeout, true);
    }
    Client client(int port, Duration timeout, boolean verifyIdentity) {
        if (port != QA_PORT && !RedisFaultProxy.owns(port)) throw new IllegalArgumentException("Unapproved endpoint");
        RedisStandaloneConfiguration server = new RedisStandaloneConfiguration(HOST, port);
        server.setDatabase(0);
        String password = System.getenv("QA_REDIS_PASSWORD");
        if (password == null || password.isBlank()) throw new IllegalStateException("Private QA credential required");
        server.setPassword(password);
        LettuceClientConfiguration config = LettuceClientConfiguration.builder()
                .clientResources(resources).commandTimeout(timeout).shutdownTimeout(Duration.ofMillis(100))
                .clientOptions(ClientOptions.builder().protocolVersion(ProtocolVersion.RESP2).autoReconnect(false)
                        .socketOptions(SocketOptions.builder().connectTimeout(Duration.ofMillis(500)).build()).build()).build();
        LettuceConnectionFactory factory = new LettuceConnectionFactory(server, config);
        factory.afterPropertiesSet();
        factory.start();
        StringRedisTemplate template = new StringRedisTemplate(factory);
        Client result = new Client(factory, template);
        clients.add(result);
        if (!verifyIdentity) return result; // Only a deliberately unavailable fixture endpoint.
        assertThat(template.execute((RedisCallback<String>) c -> c.ping())).isEqualTo("PONG");
        Properties identity = template.execute((RedisCallback<Properties>) c -> c.serverCommands().info("server"));
        assertThat(identity).isNotNull();
        assertThat(identity.getProperty("redis_version")).isEqualTo("7.4.7");
        assertThat(identity.getProperty("run_id")).isEqualTo(System.getProperty("qa.redis.runId"));
        return result;
    }

    RedisAuthenticationFailureStore store(Client client) {
        return new RedisAuthenticationFailureStore(client.template, new AuthenticationHistoryKeyHasher(properties), properties);
    }
    RedisAuthenticationFailureStore store() { return store(primary); }

    String key(String category, String scope, String canonicalValue) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(PEPPER.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            String key = properties.getKeyPrefix() + ':' + category + ':' + HexFormat.of().formatHex(
                    mac.doFinal((scope + '\0' + canonicalValue).getBytes(StandardCharsets.UTF_8)));
            observedKeys.add(key);
            return key;
        } catch (Exception e) { throw new IllegalStateException(e); }
    }
    String event(String id) { return key("event", "event", id.trim()); }
    String subject(String id) { return key("failure:subject", "subject", id.trim()); }
    String ip(String canonical) { return key("failure:ip", "ip", canonical); }
    void track(String event, String subject, String canonicalIp) {
        event(event); if (subject != null) subject(subject); ip(canonicalIp);
    }
    void seed(String key, String value) {
        assertThat(key).startsWith(properties.getKeyPrefix() + ':');
        primary.template.opsForValue().set(key, value, Duration.ofSeconds(60));
    }
    String get(String key) { return primary.template.opsForValue().get(key); }
    long ttl(String key) { return Objects.requireNonNull(primary.template.getExpire(key, TimeUnit.MILLISECONDS)); }
    void counters(String subject, String ip, long expectedSubject, long expectedIp) {
        assertThat(store().countBySubject(subject)).isEqualTo(expectedSubject);
        assertThat(store().countBySourceIp(ip)).isEqualTo(expectedIp);
    }
    void evidence(String detail) { System.out.println("QA01C2 " + scenario + " | " + detail); }
    static String scriptSha1() {
        var script = (org.springframework.data.redis.core.script.RedisScript<?>) org.springframework.test.util.ReflectionTestUtils
                .getField(RedisAuthenticationFailureStore.class, "RECORD_FAILURE_SCRIPT");
        return Objects.requireNonNull(script).getSha1();
    }
    static String rootCause(Throwable error) {
        while (error.getCause() != null) error = error.getCause();
        return error.getClass().getSimpleName() + ": " + error.getMessage();
    }

    static AuthenticationHistoryRiskProperties thresholds() {
        AuthenticationHistoryRiskProperties p = new AuthenticationHistoryRiskProperties();
        p.setSubjectMediumMinimum(3); p.setSubjectHighMinimum(5);
        p.setSourceIpMediumMinimum(10); p.setSourceIpHighMinimum(20);
        p.setMediumScore(new java.math.BigDecimal("50")); p.setHighScore(new java.math.BigDecimal("100"));
        return p;
    }

    @AfterEach
    void inspectAndClose() {
        try {
            if (primary != null) for (String key : observedKeys) {
                String type = primary.template.type(key).code();
                String value = type.equals("string") ? get(key) : "<" + type + ">";
                long pttl = ttl(key);
                evidence("KEY " + key + " type=" + type + " value=" + value + " pttl=" + pttl);
                // Bound only non-expiring keys owned by this fixture, after evidence/assertions.
                if (pttl == -1) primary.template.expire(key, Duration.ofSeconds(90));
            }
            if (primary != null && commandsBefore != null) {
                Properties after = primary.template.execute((RedisCallback<Properties>) c -> c.serverCommands().info("commandstats"));
                var exists = primary.template.execute((RedisCallback<List<Boolean>>) c -> c.scriptingCommands().scriptExists(scriptSha1()));
                evidence("LUA redisCommandstatsDelta EVALSHA=" + (calls(after, "evalsha") - calls(commandsBefore, "evalsha"))
                        + " EVAL=" + (calls(after, "eval") - calls(commandsBefore, "eval")) + " productionScriptExists=" + exists);
            }
        } finally {
            for (Client client : clients) client.factory.destroy();
            if (resources != null) resources.shutdown();
        }
    }
    private static long calls(Properties info, String command) {
        String stats = info.getProperty("cmdstat_" + command, "calls=0");
        for (String part : stats.split(",")) if (part.startsWith("calls=")) return Long.parseLong(part.substring(6));
        throw new IllegalStateException("Redis command stats malformed");
    }

    static final class Client {
        final LettuceConnectionFactory factory;
        final StringRedisTemplate template;
        Client(LettuceConnectionFactory factory, StringRedisTemplate template) { this.factory = factory; this.template = template; }
        long id() {
            return Objects.requireNonNull(template.execute((RedisCallback<Long>) c -> {
                @SuppressWarnings("unchecked")
                var commands = (io.lettuce.core.api.async.RedisAsyncCommands<byte[], byte[]>) c.getNativeConnection();
                return commands.clientId().toCompletableFuture().join();
            }));
        }
    }
}
