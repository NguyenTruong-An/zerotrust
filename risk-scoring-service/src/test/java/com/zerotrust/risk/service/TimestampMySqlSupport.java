package com.zerotrust.risk.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.risk.migration.SubjectIdentityMigrationPreflight;
import org.flywaydb.core.Flyway;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import static org.assertj.core.api.Assertions.*;

/** Test-only fail-closed guard; no migration, cleanup, repair or resource creation. */
public class TimestampMySqlSupport implements ApplicationContextInitializer<ConfigurableApplicationContext> {
    public static final AtomicReference<Instant> NOW=TimestampLifecyclePrecisionContract.NOW;
    static final List<String> TABLES=List.of("subject_device_trust","known_devices","device_trust_revocations","authentication_success_events","flyway_schema_history");
    static final ThreadLocal<Map<String,List<String>>> BEFORE=new ThreadLocal<>();
    static final ThreadLocal<String> STRUCTURE=new ThreadLocal<>();
    public static Map<String,Object> manifest() {
        try {
            if(!"APPROVED".equals(System.getProperty("postfix03b.native")))throw new IllegalStateException("Native permission missing");
            byte[] bytes=Files.readAllBytes(Path.of(System.getProperty("postfix03b.manifest")));
            if(!digest(bytes).equals(System.getProperty("postfix03b.manifestSHA")))throw new IllegalStateException("Native manifest SHA mismatch");
            Map<String,Object> m=new ObjectMapper().readValue(bytes,new TypeReference<>(){});
            if(!Boolean.TRUE.equals(m.get("approved"))||!"POSTFIX-03B".equals(m.get("owner")))throw new IllegalStateException("Native owner/approval mismatch");
            if(!UUID.fromString(m.get("run_uuid").toString()).toString().equals(System.getProperty("postfix03b.runUUID")))throw new IllegalStateException("Native run mismatch");
            if(!"zt-mysql-qa-postfix03b".equals(m.get("container_name"))||!"127.0.0.1:3310".equals(m.get("endpoint")))throw new IllegalStateException("Native resource mismatch");
            return m;
        } catch(Exception e) {throw new IllegalStateException("POSTFIX03B native guard rejected configuration",e);}
    }
    static String schema() {return System.getProperty("postfix03b.schema");}
    static List<String> schemas(Map<String,Object> m) {
        @SuppressWarnings("unchecked") List<String> list=(List<String>)m.get("schemas");
        String prefix="pf03b_"+m.get("run_uuid").toString().substring(0,8)+"_";
        if(list==null||!new HashSet<>(list).equals(Set.of(prefix+"baseline",prefix+"lifecycle",prefix+"identity"))||list.size()!=3)throw new IllegalStateException("Native schema allowlist mismatch");
        return list;
    }
    static Connection connect() throws Exception {
        Map<String,Object> m=manifest();
        if(!schemas(m).contains(schema()))throw new IllegalStateException("Unapproved native schema");
        String expected="jdbc:mysql://127.0.0.1:3310/"+schema()+"?serverTimezone=UTC";
        if(!expected.equals(System.getenv("PF03B_MYSQL_URL")))throw new IllegalStateException("Unexpected native JDBC URL");
        String password=System.getenv("PF03B_MYSQL_PASSWORD");
        if(password==null||password.isBlank())throw new IllegalStateException("Native credentials missing");
        return DriverManager.getConnection(expected,"pf03b_app",password);
    }
    static String scalar(Connection c,String sql) throws Exception {
        try(var s=c.createStatement();var r=s.executeQuery(sql)){if(!r.next())throw new IllegalStateException("Native metadata missing");return r.getString(1);}
    }
    static void validate(Connection c) throws Exception {
        var m=manifest();
        if(!"8.0.46".equals(c.getMetaData().getDatabaseProductVersion())||!schema().equals(c.getCatalog()))throw new IllegalStateException("Native engine/database drift");
        if(!m.get("server_uuid").equals(scalar(c,"SELECT @@server_uuid")))throw new IllegalStateException("Native server UUID drift");
        if(!scalar(c,"SELECT CURRENT_USER()").startsWith("pf03b_app@"))throw new IllegalStateException("Native account drift");
        if(!"REPEATABLE-READ".equals(scalar(c,"SELECT @@transaction_isolation")))throw new IllegalStateException("Native isolation drift");
        if(!List.of("+00:00","UTC").contains(scalar(c,"SELECT @@session.time_zone")))throw new IllegalStateException("Native timezone drift");
        if(!m.get("sql_mode").equals(scalar(c,"SELECT @@session.sql_mode")))throw new IllegalStateException("Native SQL mode drift");
        String h="`"+schema()+"`.flyway_schema_history";
        if(!"5".equals(scalar(c,"SELECT COUNT(*) FROM "+h))||!"1".equals(scalar(c,"SELECT COUNT(*) FROM "+h+" WHERE version='5' AND checksum=661092940 AND success=1")))throw new IllegalStateException("Native migration history mismatch");
    }
    @Override public void initialize(ConfigurableApplicationContext context) {
        try(var c=connect()) {
            validate(c);assertBudget(c);
            var data=new ObjectMapper().convertValue(manifest().get("source_sha256"),new TypeReference<Map<String,String>>(){});
            for(var file:data.entrySet())if(!digest(Files.readAllBytes(Path.of(System.getProperty("postfix03b.sourceRoot"),file.getKey()))).equals(file.getValue()))throw new IllegalStateException("Native source integrity mismatch");
            Flyway.configure().dataSource(System.getenv("PF03B_MYSQL_URL"),"pf03b_app",System.getenv("PF03B_MYSQL_PASSWORD")).locations("classpath:db/migration").cleanDisabled(true).load().validate();
        } catch(Exception e){throw new IllegalStateException("POSTFIX03B native preflight STOP",e);}
    }
    public static void own(String subject) {
        @SuppressWarnings("unchecked") List<String> allowed=(List<String>)manifest().get("identity_subjects");
        if(allowed==null||!allowed.contains(subject))throw new IllegalStateException("Unapproved identity fixture");
        try(var c=connect();var p=c.prepareStatement("SELECT (SELECT COUNT(*) FROM subject_device_trust WHERE subject_id=?)+(SELECT COUNT(*) FROM known_devices WHERE subject_id=?)+(SELECT COUNT(*) FROM device_trust_revocations WHERE subject_id=?)")) {
            p.setString(1,subject);p.setString(2,subject);p.setString(3,subject);
            try(var r=p.executeQuery()){r.next();assertThat(r.getLong(1)).as("fresh exact subject").isZero();}
        }catch(Exception e){throw new IllegalStateException("Identity ownership guard rejected",e);}
    }
    static String structure(Connection c) throws Exception {
        StringBuilder result=new StringBuilder();
        for(String table:TABLES)try(var s=c.createStatement();var r=s.executeQuery("SHOW CREATE TABLE `"+table+"`")){
            r.next();result.append(table).append(r.getString(2).replaceAll(" AUTO_INCREMENT=\\d+",""));
        }
        return digest(result.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
    static Map<String,List<String>> rows(Connection c) throws Exception {
        Map<String,List<String>> result=new TreeMap<>();
        for(String table:TABLES)try(var s=c.createStatement();var r=s.executeQuery("SELECT * FROM `"+table+"`")) {
            var meta=r.getMetaData();List<String> values=new ArrayList<>();
            while(r.next()){
                Map<String,String> row=new TreeMap<>();for(int n=1;n<=meta.getColumnCount();n++)row.put(meta.getColumnName(n),r.getString(n));
                values.add(digest(new ObjectMapper().writeValueAsBytes(row)));
            }
            Collections.sort(values);result.put(table,values);
        }
        return result;
    }
    static void assertBudget(Connection c) throws Exception {
        var m=manifest();@SuppressWarnings("unchecked") List<String> allowed=(List<String>)m.get("identity_subjects");
        String prefix="pf03b-"+m.get("run_uuid")+"-";long total=0;
        @SuppressWarnings("unchecked") Map<String,Integer> caps=(Map<String,Integer>)m.get("application_table_caps");
        for(String table:SubjectIdentityMigrationPreflight.TABLES) {
            long count=0;
            for(String db:schemas(m))try(var s=c.createStatement();var r=s.executeQuery("SELECT subject_id FROM `"+db+"`.`"+table+"`")){
                while(r.next()) {String subject=r.getString(1);if(!subject.toLowerCase(Locale.ROOT).startsWith(prefix)&&!allowed.contains(subject))throw new IllegalStateException("Unexpected native row owner");count++;}
            }
            if(count>caps.get(table))throw new IllegalStateException("Native table row cap exceeded");total+=count;
        }
        if(total>215)throw new IllegalStateException("Native application row budget exceeded");
        long histories=0;for(String db:schemas(m))histories+=Long.parseLong(scalar(c,"SELECT COUNT(*) FROM `"+db+"`.flyway_schema_history"));
        if(histories>15||total+histories>230)throw new IllegalStateException("Native retained row budget exceeded");
    }
    static void before() throws Exception {try(var c=connect()){validate(c);assertBudget(c);BEFORE.set(rows(c));STRUCTURE.set(structure(c));}}
    static void after() throws Exception {
        try(var c=connect()){
            validate(c);assertBudget(c);var after=rows(c);
            assertThat(structure(c)).as("native schema preservation").isEqualTo(STRUCTURE.get());
            BEFORE.get().forEach((table,old)->{
                for(String hash:new HashSet<>(old))assertThat(Collections.frequency(after.get(table),hash)).as("old row hash preserved in %s",table).isGreaterThanOrEqualTo(Collections.frequency(old,hash));
            });
        } finally {BEFORE.remove();STRUCTURE.remove();}
    }
    static String digest(byte[] bytes) throws Exception {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
}
