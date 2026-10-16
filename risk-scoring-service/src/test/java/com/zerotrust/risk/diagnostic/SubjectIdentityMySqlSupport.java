package com.zerotrust.risk.diagnostic;

import com.fasterxml.jackson.databind.ObjectMapper;
import db.migration.V5__isolate_subject_identity;
import com.zerotrust.risk.migration.SubjectIdentityMigrationPreflight;
import org.flywaydb.core.Flyway;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.datasource.AbstractDataSource;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Gate B only. No creation, migration, cleanup or connection to shared3308/operational3307. */
public class SubjectIdentityMySqlSupport implements ApplicationContextInitializer<ConfigurableApplicationContext> {
    public static final AtomicReference<Instant> NOW = new AtomicReference<>(Instant.parse("2026-10-16T00:00:00.123456Z"));
    private static final ObjectMapper JSON = new ObjectMapper();
    public static final String OWNER = "POSTFIX-03A";
    public static final String CONTAINER = "zt-mysql-qa-postfix03a";
    private static final Set<String> TABLES = Set.of("subject_device_trust", "known_devices", "device_trust_revocations", "authentication_success_events", "flyway_schema_history");

    @SuppressWarnings("unchecked")
    public static Map<String,Object> manifest() {
        require("APPROVED".equals(System.getProperty("postfix03a.gateB")), "INDEPENDENT_GATE_B_REQUIRED");
        try {
            byte[] bytes=Files.readAllBytes(Path.of(System.getProperty("postfix03a.manifest")));
            require(digest(bytes).equals(System.getProperty("postfix03a.manifest.sha256")), "MANIFEST_HASH_MISMATCH");
            Map<String,Object> manifest=JSON.readValue(bytes,Map.class);
            require(OWNER.equals(manifest.get("owner")) && "APPROVED".equals(manifest.get("gateB")), "MANIFEST_NOT_APPROVED");
            require(java.util.UUID.fromString(manifest.get("run_uuid").toString()).toString().equals(manifest.get("run_uuid")), "INVALID_FRESH_RUN_ID");
            require(new V5__isolate_subject_identity().getChecksum().equals(((Number)manifest.get("migration_checksum")).intValue()), "CANDIDATE_CHECKSUM_MISMATCH");
            return manifest;
        } catch(Exception ex) { throw new IllegalStateException("POSTFIX03A_MANIFEST_REFUSED",ex); }
    }

    public static String digest(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static void containerIdentity(Map<String,Object> m) throws Exception {
        String format="{{json .Id}}|{{json .Config.Hostname}}|{{json .Config.Labels}}|{{json .HostConfig.PortBindings}}|{{json .State}}|{{json .NetworkSettings.Networks}}|{{json .Mounts}}|{{json .Image}}";
        String[] parts=inspect("inspect","--format",format,CONTAINER).split("\\|",8);
        require(parts.length==8,"CONTAINER_METADATA");
        require(JSON.readValue(parts[0],String.class).equals(m.get("container_id")),"CONTAINER_ID_CHANGED");
        require(CONTAINER.equals(JSON.readValue(parts[1],String.class)),"HOSTNAME_MISMATCH");
        Map<?,?> labels=JSON.readValue(parts[2],Map.class),ports=JSON.readValue(parts[3],Map.class),state=JSON.readValue(parts[4],Map.class);
        require(OWNER.equals(labels.get("com.zerotrust.qa.owner")),"OWNER_MISMATCH");
        require(ports.size()==1 && ports.get("3306/tcp") instanceof List<?> bindings && bindings.size()==1
                && bindings.get(0) instanceof Map<?,?> bind && "127.0.0.1".equals(bind.get("HostIp")) && "3309".equals(bind.get("HostPort")),"PORT_MISMATCH");
        require(Boolean.TRUE.equals(state.get("Running")) && m.get("started_at").equals(state.get("StartedAt")),"RESTART_REVALIDATION_REQUIRED");
        Map<?,?> networks=JSON.readValue(parts[5],Map.class);
        String network="zt-mysql-qa-postfix03a-net",volume="zt-mysql-qa-postfix03a-data";
        require(networks.keySet().equals(Set.of(network)),"NETWORK_MISMATCH");
        List<?> mounts=JSON.readValue(parts[6],List.class);
        require(mounts.stream().anyMatch(x->x instanceof Map<?,?> mount && volume.equals(mount.get("Name")) && "/var/lib/mysql".equals(mount.get("Destination"))),"VOLUME_MISMATCH");
        require(JSON.readValue(parts[7],String.class).equals(m.get("image_id")),"IMAGE_MISMATCH");
        Map<?,?> net=JSON.readValue(inspect("network","inspect","--format","{{json .}}",network),Map.class);
        require(OWNER.equals(((Map<?,?>)net.get("Labels")).get("com.zerotrust.qa.owner"))
                && ((Map<?,?>)net.get("Containers")).keySet().equals(Set.of(m.get("container_id"))),"NETWORK_OWNER_OR_MEMBER_MISMATCH");
        Map<?,?> vol=JSON.readValue(inspect("volume","inspect","--format","{{json .Labels}}",volume),Map.class);
        require(OWNER.equals(vol.get("com.zerotrust.qa.owner")),"VOLUME_OWNER_MISMATCH");
    }

    private static String inspect(String... args) throws Exception {
        List<String> command=new ArrayList<>();command.add("docker");command.addAll(List.of(args));
        Process process=new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        var output=java.util.concurrent.CompletableFuture.supplyAsync(()->{
            try{return process.getInputStream().readAllBytes();}catch(java.io.IOException ex){throw new IllegalStateException("INSPECT_READ_FAILED",ex);}
        });
        if(!process.waitFor(10,TimeUnit.SECONDS)){process.destroyForcibly();throw new IllegalStateException("DOCKER_INSPECT_TIMEOUT");}
        require(process.exitValue()==0,"DOCKER_INSPECT_FAILED");
        return new String(output.get(2,TimeUnit.SECONDS),StandardCharsets.UTF_8).trim();
    }

    @SuppressWarnings("unchecked")
    public static String schema(String scenario) {
        var m=manifest();var schemas=(Map<String,String>)m.get("schemas");String schema=schemas.get(scenario);
        String prefix="pf03a_"+m.get("run_uuid").toString().replace("-","").substring(0,8)+"_";
        require(schema!=null && schema.startsWith(prefix) && schema.matches("[a-z0-9_]{1,64}"),"UNAPPROVED_SCHEMA");
        return schema;
    }
    public static Connection connect(String scenario) throws Exception {
        var m=manifest();
        if(Set.of("upgrade","production").contains(scenario))require("APPROVED".equals(m.get("history_INSERT")),"INDEPENDENT_HISTORY_INSERT_PERMISSION_REQUIRED");
        containerIdentity(m);
        String schema=schema(scenario),url="jdbc:mysql://127.0.0.1:3309/"+schema+"?serverTimezone=UTC";
        String password=System.getenv("PF03A_MYSQL_PASSWORD");require(password!=null&&!password.isBlank(),"PRIVATE_CREDENTIAL_REQUIRED");
        Properties p=new Properties();p.setProperty("user","pf03a_app");p.setProperty("password",password);
        p.setProperty("connectTimeout","3000");p.setProperty("socketTimeout","30000");
        Connection c=DriverManager.getConnection(url,p);
        try(var s=c.createStatement();var r=s.executeQuery("SELECT VERSION(),DATABASE(),CURRENT_USER(),@@hostname,@@transaction_isolation")) {
            require(r.next()&&"8.0.46".equals(r.getString(1))&&schema.equals(r.getString(2))&&"pf03a_app@%".equals(r.getString(3))
                    &&CONTAINER.equals(r.getString(4))&&"REPEATABLE-READ".equals(r.getString(5)),"DATABASE_IDENTITY_MISMATCH");
        } catch(Exception ex) { c.close();throw ex; }
        return c;
    }
    public static Connection connect() throws Exception { return connect(manifest().get("active_scenario").toString()); }
    public static DataSource dataSource(String scenario) {
        return new AbstractDataSource() {
            @Override public Connection getConnection() throws java.sql.SQLException {
                try{return connect(scenario);}catch(Exception ex){throw new java.sql.SQLException("POSTFIX03A_CONNECTION_GUARD_REFUSED",ex);}
            }
            @Override public Connection getConnection(String user,String password) { throw new UnsupportedOperationException("Fixed private QA identity only"); }
        };
    }
    public static String schemaFingerprint(Connection c) throws Exception {
        Map<String,String> creates=new TreeMap<>();
        try(var s=c.createStatement();var rows=s.executeQuery("SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE()")) {
            while(rows.next()) {
                String table=rows.getString(1);require(TABLES.contains(table),"UNEXPECTED_TABLE");
                try(var ds=c.createStatement();var ddl=ds.executeQuery("SHOW CREATE TABLE `"+table+"`")) {ddl.next();creates.put(table,ddl.getString(2).replaceAll("AUTO_INCREMENT=\\d+","AUTO_INCREMENT=<counter>"));}
            }
        }
        return digest(JSON.writeValueAsBytes(creates));
    }
    public static void own(String subject) {
        var m=manifest();String scope=System.getProperty("diagnosticScope");
        @SuppressWarnings("unchecked") var pairs=(List<Map<String,Object>>)m.get("identity_pairs");
        boolean permitted=pairs.stream().anyMatch(p->scope!=null&&scope.equals(p.get("scope"))&&(subject.equals(p.get("left"))||subject.equals(p.get("right"))));
        require(permitted,"SUBJECT_OUTSIDE_APPROVED_PAIR");
        try(var c=connect()) {
            for(String table:List.of("known_devices","subject_device_trust","device_trust_revocations","authentication_success_events")) {
                try(var s=c.prepareStatement("SELECT COUNT(*) FROM "+table+" WHERE subject_id=?")) {
                    s.setString(1,subject);try(var r=s.executeQuery()){r.next();require(r.getLong(1)==0,"SUBJECT_NOT_FRESH");}
                }
            }
        } catch(Exception ex) {throw new IllegalStateException("POSTFIX03A_FRESH_OWNERSHIP_REFUSED",ex);}
    }
    public static void assertBudget(Connection c,String scenario) throws Exception {
        var m=manifest();var budgets=(Map<?,?>)((Map<?,?>)m.get("row_budgets")).get(scenario);
        for(String table:TABLES) {
            require(budgets.containsKey(table),"ROW_BUDGET_ABSENT");
            try(var s=c.createStatement();var r=s.executeQuery("SELECT COUNT(*) FROM "+table)) {r.next();require(r.getLong(1)<=((Number)budgets.get(table)).longValue(),"ROW_BUDGET_EXCEEDED");}
        }
    }
    @Override public void initialize(ConfigurableApplicationContext context) {
        var m=manifest();String scenario=m.get("active_scenario").toString();
        require(("jdbc:mysql://127.0.0.1:3309/"+schema(scenario)+"?serverTimezone=UTC").equals(System.getenv("PF03A_MYSQL_URL")),"SPRING_URL_MISMATCH");
        try(var c=connect(scenario)) {
            c.setReadOnly(true);
            require(schemaFingerprint(c).equals(((Map<?,?>)m.get("schema_fingerprints")).get(scenario)),"SCHEMA_FINGERPRINT_MISMATCH");
            var baseline=SubjectIdentityMigrationPreflight.snapshot(c);
            SubjectIdentityMigrationPreflight.verifyAfterStatement(c,new SubjectIdentityMigrationPreflight.Plan(true,baseline,SubjectIdentityMigrationPreflight.DDL),4);
            try(var s=c.createStatement();var r=s.executeQuery("SELECT checksum,success FROM flyway_schema_history WHERE version='5'")) {
                require(r.next()&&r.getInt(1)==new V5__isolate_subject_identity().getChecksum()&&r.getBoolean(2)&&!r.next(),"SUCCESSFUL_EXACT_V5_HISTORY_REQUIRED");
            }
            Flyway.configure().dataSource(dataSource(scenario)).locations("classpath:db/migration").cleanDisabled(true).load().validate();
        }catch(Exception ex){throw new IllegalStateException("POSTFIX03A_NATIVE_STARTUP_REFUSED",ex);}
    }
    public static void require(boolean valid,String reason) {if(!valid)throw new IllegalStateException("POSTFIX03A_"+reason);}
    @TestConfiguration public static class TimeConfig {
        @Bean @Primary Clock subjectIdentityNativeClock() {
            return new Clock() {
                @Override public ZoneId getZone(){return ZoneOffset.UTC;}
                @Override public Clock withZone(ZoneId zone){require(ZoneOffset.UTC.equals(zone),"UTC_CLOCK_REQUIRED");return this;}
                @Override public Instant instant(){return NOW.get();}
            };
        }
    }
}
