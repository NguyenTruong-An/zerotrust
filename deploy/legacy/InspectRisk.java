import com.zerotrust.risk.migration.SubjectIdentityMigrationPreflight;
import db.migration.V5__isolate_subject_identity;
import java.nio.file.*;
import java.sql.*;
import java.util.Properties;

/** Read-only inspection only. Never invokes Flyway.migrate or executes returned DDL. */
public final class InspectRisk {
    public static void main(String[] args) throws Exception {
        Properties p = new Properties();
        try (var input = Files.newInputStream(Path.of(args[0]))) { p.load(input); }
        String url = p.getProperty("url");
        if (!(url.startsWith("jdbc:mysql://zerotrust-legacy-restore-20261026-1344ea0d-risk-db:3306/risk_db?")
                || url.startsWith("jdbc:mysql://risk-db:3306/risk_db?"))
                || !url.contains("sslMode=REQUIRED")) throw new IllegalStateException("UNAPPROVED_INSPECTION_ENDPOINT");
        if (new V5__isolate_subject_identity().getChecksum() != 661092940)
            throw new IllegalStateException("IMMUTABLE_V5_CHECKSUM_DRIFT");
        try (var c = DriverManager.getConnection(url, p.getProperty("username"), p.getProperty("password"))) {
            c.setReadOnly(true);
            String writer = p.getProperty("writer.username");
            if (writer == null || writer.isBlank()) throw new IllegalStateException("MISSING_WRITER_IDENTITY");
            try (var s = c.prepareStatement("SELECT COUNT(*) FROM performance_schema.threads WHERE PROCESSLIST_USER=?")) {
                s.setString(1, writer);
                try (var rows = s.executeQuery()) {
                    rows.next();
                    if (rows.getLong(1) != 0) throw new IllegalStateException("WRITER_SESSIONS_PRESENT");
                }
            }
            var plan = SubjectIdentityMigrationPreflight.inspect(c, true);
            System.out.print("{\"read_only\":true,\"V5_checksum\":661092940,\"preflight\":\"PASS\",\"snapshot_sha256\":\"");
            System.out.print(plan.baseline().sha256());
            System.out.print("\",\"proposed_DDL_count\":" + plan.statements().size() + ",\"tables\":{");
            boolean first = true;
            for (var entry : plan.baseline().tables().entrySet()) {
                if (!first) System.out.print(","); first = false;
                System.out.print("\"" + entry.getKey() + "\":" + entry.getValue().size());
            }
            System.out.println("},\"DDL_executed\":0}");
        }
    }
}
