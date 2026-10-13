package com.zerotrust.risk.audit.mysql;

import org.flywaydb.core.Flyway;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;

import java.sql.*;
import java.time.Instant;
import java.util.*;

/** Before Spring/Flyway writes: fail closed on target identity, unknown tables or unowned rows. */
public class MySqlQaBootstrap implements ApplicationContextInitializer<ConfigurableApplicationContext> {
    static final String URL="jdbc:mysql://127.0.0.1:3308/risk_qa?serverTimezone=UTC";
    static final String HOSTNAME="zt-mysql-qa-fix03";
    static final Instant NOW=Instant.parse("2026-10-11T08:00:00.123456Z");
    static final String RUN=UUID.randomUUID().toString();
    static final String LEGACY="qa01c1-legacy";
    static final Set<String> TABLES=Set.of("known_devices","authentication_success_events","subject_device_trust",
            "device_trust_revocations","flyway_schema_history","qa01c1_fixture_manifest","qa01c1_precision_fixture");

    static String password() {
        String value=System.getenv("QA_MYSQL_PASSWORD");
        if(value==null || value.isBlank()) throw new IllegalStateException("QA credential absent; no H2 fallback");
        return value;
    }
    static Connection connect() throws SQLException {
        Properties p=new Properties(); p.setProperty("user","risk_qa");p.setProperty("password",password());
        p.setProperty("connectTimeout","3000");p.setProperty("socketTimeout","30000");
        try {return DriverManager.getConnection(URL,p);} finally {p.remove("password");}
    }
    static void identity(Connection c) throws SQLException {
        try(Statement s=c.createStatement();ResultSet r=s.executeQuery("SELECT VERSION(),DATABASE(),CURRENT_USER(),@@transaction_isolation,@@hostname")) {
            r.next();
            if(!"MySQL".equals(c.getMetaData().getDatabaseProductName()) || !"8.0.46".equals(r.getString(1))
                    || !"risk_qa".equals(r.getString(2)) || !"risk_qa@%".equals(r.getString(3))
                    || !"REPEATABLE-READ".equals(r.getString(4)) || !HOSTNAME.equals(r.getString(5)))
                throw new IllegalStateException("QA identity mismatch; refuse all fixture writes");
        }
    }
    @Override public void initialize(ConfigurableApplicationContext context) {
        try(Connection c=connect()) {
            identity(c);
            Set<String> present=new HashSet<>();
            try(Statement s=c.createStatement();ResultSet r=s.executeQuery("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()")) {
                while(r.next()) present.add(r.getString(1));
            }
            if(present.isEmpty()) {
                System.out.println("MYSQL AUDIT GUARD identity=verified schema=empty; migrate V1 before legacy fixture");
                Flyway.configure().dataSource(URL,"risk_qa",password()).locations("classpath:db/migration")
                        .cleanDisabled(true).target("1").load().migrate();
                try(Statement s=c.createStatement()) {
                    s.execute("CREATE TABLE qa01c1_fixture_manifest (subject_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin PRIMARY KEY, run_id VARCHAR(36) NOT NULL, owner VARCHAR(16) NOT NULL) ENGINE=InnoDB");
                    s.execute("CREATE TABLE qa01c1_precision_fixture (fixture_key VARCHAR(100) PRIMARY KEY, numeric_value DECIMAL(7,4), time_value TIMESTAMP(6)) ENGINE=InnoDB");
                }
                own(c,LEGACY);
                try(PreparedStatement p=c.prepareStatement("INSERT INTO known_devices(subject_id,device_fingerprint_hash,status,first_seen_at,last_seen_at,trusted_at,version) VALUES(?,?,'TRUSTED',?,?,?,0)")) {
                    p.setString(1,LEGACY);p.setString(2,"a".repeat(64));
                    for(int i=3;i<=5;i++) p.setTimestamp(i,Timestamp.from(NOW),Calendar.getInstance(TimeZone.getTimeZone("UTC")));
                    p.executeUpdate();
                }
            } else {
                if(!TABLES.containsAll(present) || !present.contains("qa01c1_fixture_manifest"))
                    throw new IllegalStateException("Nonempty QA schema lacks recognized fixture ownership; no cleanup/overwrite");
                for(String table:List.of("known_devices","authentication_success_events","subject_device_trust","device_trust_revocations")) {
                    if(!present.contains(table)) continue;
                    String sql="SELECT COUNT(*) FROM "+table+" d LEFT JOIN qa01c1_fixture_manifest m ON BINARY d.subject_id=BINARY m.subject_id WHERE m.subject_id IS NULL OR m.owner <> '01C1'";
                    try(Statement s=c.createStatement();ResultSet r=s.executeQuery(sql)) {
                        r.next();if(r.getLong(1)!=0) throw new IllegalStateException("Unowned rows in "+table+"; refuse fixture writes");
                    }
                }
                try(Statement s=c.createStatement();ResultSet r=s.executeQuery("SELECT COUNT(*) FROM qa01c1_precision_fixture WHERE fixture_key NOT LIKE 'qa01c1-%'")) {
                    r.next();if(r.getLong(1)!=0) throw new IllegalStateException("Unowned precision fixtures; refuse writes");
                }
                System.out.println("MYSQL AUDIT GUARD identity=verified nonemptySchema=only-owned-fixtures; preserve all rows");
                repairOwnedHarnessFixtures(c);
            }
        } catch(SQLException e) {throw new IllegalStateException("QA guard SQL failure state="+e.getSQLState()+" vendor="+e.getErrorCode());}
    }
    static void own(Connection c,String subject) throws SQLException {
        try(PreparedStatement p=c.prepareStatement("INSERT INTO qa01c1_fixture_manifest(subject_id,run_id,owner) VALUES(?,?,'01C1')")) {
            p.setString(1,subject);p.setString(2,RUN);p.executeUpdate();
        }
    }
    // Repairs ONLY two mistakes in this new audit harness, after identity/row ownership checks.
    // No production table definition, business oracle, migration or old test is changed.
    private static void repairOwnedHarnessFixtures(Connection c) throws SQLException {
        try(Statement s=c.createStatement();ResultSet r=s.executeQuery("SELECT COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='qa01c1_fixture_manifest' AND COLUMN_NAME='subject_id'")) {
            r.next();if("utf8mb4_bin".equals(r.getString(1))) {
                try(Statement alter=c.createStatement()) {
                    alter.execute("ALTER TABLE qa01c1_fixture_manifest MODIFY subject_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin NOT NULL");
                }
                System.out.println("MYSQL HARNESS_REPAIR ownership-manifest PAD SPACE -> NO PAD; no rows deleted");
            }
        }
        try(PreparedStatement p=c.prepareStatement("SELECT first_seen_at,last_seen_at,trusted_at FROM known_devices WHERE BINARY subject_id=BINARY ? AND device_fingerprint_hash=? AND status='TRUSTED' AND version=0")) {
            p.setString(1,LEGACY);p.setString(2,"a".repeat(64));
            try(ResultSet r=p.executeQuery()) {
                if(!r.next())throw new IllegalStateException("Legacy fixture unexpectedly changed; refuse repair");
                Calendar utc=Calendar.getInstance(TimeZone.getTimeZone("UTC"));
                Instant first=r.getTimestamp(1,utc).toInstant(),last=r.getTimestamp(2,utc).toInstant(),trusted=r.getTimestamp(3,utc).toInstant();
                if(!first.equals(NOW)) {
                    Instant originalHarnessError=NOW.plusSeconds(7*3600);
                    if(!first.equals(originalHarnessError)||!last.equals(first)||!trusted.equals(first))throw new IllegalStateException("Unknown legacy fixture timestamps; refuse overwrite");
                    try(PreparedStatement fix=c.prepareStatement("UPDATE known_devices SET first_seen_at=?,last_seen_at=?,trusted_at=? WHERE BINARY subject_id=BINARY ? AND device_fingerprint_hash=? AND version=0")) {
                        for(int i=1;i<=3;i++)fix.setTimestamp(i,Timestamp.from(NOW),utc);fix.setString(4,LEGACY);fix.setString(5,"a".repeat(64));
                        if(fix.executeUpdate()!=1)throw new IllegalStateException("Fixture correction did not match exactly one owned row");
                    }
                    System.out.println("MYSQL HARNESS_REPAIR exact owned legacy seed timezone +07 -> UTC; unchanged assertion and production migration");
                }
            }
        }
    }
}
