import org.flywaydb.core.Flyway;
import java.nio.file.*;
import java.sql.*;
import java.util.Properties;

/** Run only after an approved copy and any separately approved reconciliation pass V5 inspection. */
public final class MigrateLegacyRisk {
    public static void main(String[] args) throws Exception {
        Properties p = new Properties();
        try (var in = Files.newInputStream(Path.of(args[0]))) { p.load(in); }
        if (!"zerotrust-legacy-integration-20261026".equals(p.getProperty("approved.project"))
                || !"true".equals(p.getProperty("owner.execution.approved")))
            throw new IllegalStateException("OWNER_EXECUTION_APPROVAL_REQUIRED");
        String url = p.getProperty("url");
        if (!url.startsWith("jdbc:mysql://risk-db:3306/risk_db?sslMode=VERIFY_IDENTITY"))
            throw new IllegalStateException("UNAPPROVED_DESTINATION_OR_TLS");
        if (new db.migration.V5__isolate_subject_identity().getChecksum() != 661092940)
            throw new IllegalStateException("IMMUTABLE_V5_CHECKSUM_DRIFT");
        try (var c = DriverManager.getConnection(url, p.getProperty("username"), p.getProperty("password"))) {
            c.setReadOnly(true);
            try (var s = c.prepareStatement("SELECT COUNT(*) FROM performance_schema.threads WHERE PROCESSLIST_USER=?")) {
                s.setString(1, p.getProperty("writer.username"));
                try (var r = s.executeQuery()) {
                    r.next(); if (r.getInt(1) != 0) throw new IllegalStateException("WRITERS_NOT_QUIESCED");
                }
            }
            com.zerotrust.risk.migration.SubjectIdentityMigrationPreflight.inspect(c, true);
        }
        System.setProperty("zerotrust.migration.subject-identity.writers-quiesced", "true");
        var flyway = Flyway.configure().dataSource(url, p.getProperty("username"), p.getProperty("password"))
                .locations("classpath:db/migration").cleanDisabled(true).load();
        var info = flyway.info();
        if (info.applied().length != 4 || info.pending().length != 1
                || !"5".equals(info.pending()[0].getVersion().getVersion())
                || !Integer.valueOf(661092940).equals(info.pending()[0].getChecksum()))
            throw new IllegalStateException("UNAPPROVED_MIGRATION_SET");
        int[] expected = {1185184692, -1951422130, 481224608, 1302227479};
        for (int i = 0; i < expected.length; i++) {
            var migration = info.applied()[i];
            if (!Integer.toString(i + 1).equals(migration.getVersion().getVersion())
                    || !Integer.valueOf(expected[i]).equals(migration.getChecksum())
                    || !"SUCCESS".equals(migration.getState().name()))
                throw new IllegalStateException("APPLIED_HISTORY_DRIFT");
        }
        flyway.migrate();
        flyway.validate();
        System.out.println("V5 migration completed; immutable checksum661092940. No clean/repair performed.");
    }
}
