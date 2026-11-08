import com.zerotrust.risk.migration.SubjectIdentityMigrationPreflight;
import db.migration.V5__isolate_subject_identity;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.util.concurrent.atomic.AtomicInteger;

/** Probes compiled V5 preflight with metadata-only proxies; never connects to a DB. */
public class MigrationCompatibilityAudit {
    public static void main(String[] args) throws Exception {
        var sqlCalls = new AtomicInteger();
        var metadata = (DatabaseMetaData) Proxy.newProxyInstance(
                MigrationCompatibilityAudit.class.getClassLoader(), new Class[]{DatabaseMetaData.class},
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "getDatabaseProductName" -> "MySQL";
                    case "getDatabaseProductVersion" -> "8.4.13";
                    default -> throw new AssertionError("Unexpected metadata call: " + method.getName());
                });
        var connection = (Connection) Proxy.newProxyInstance(
                MigrationCompatibilityAudit.class.getClassLoader(), new Class[]{Connection.class},
                (proxy, method, arguments) -> {
                    if (method.getName().equals("getMetaData")) return metadata;
                    sqlCalls.incrementAndGet();
                    throw new AssertionError("Preflight must reject before any SQL call");
                });
        boolean refused = false;
        try { SubjectIdentityMigrationPreflight.inspect(connection, true); }
        catch (IllegalStateException expected) {
            if (!expected.getMessage().contains("UNREVIEWED_MYSQL_VERSION")) throw expected;
            refused = true;
        }
        if (!refused || sqlCalls.get() != 0) throw new AssertionError("Unexpected compatibility behavior");
        int checksum = new V5__isolate_subject_identity().getChecksum();
        if (checksum != 661092940) throw new AssertionError("Compiled V5 checksum drift: " + checksum);
        System.out.printf("{\"result\":\"PASS_CHARACTERIZATION\",\"mysql_metadata_version\":\"8.4.13\",\"preflight_rejected\":true,\"reason\":\"UNREVIEWED_MYSQL_VERSION\",\"sql_calls\":0,\"v5_checksum\":%d,\"scope\":\"Compiled migration + metadata proxy only; not real MySQL migration/restore\"}%n", checksum);
    }
}
