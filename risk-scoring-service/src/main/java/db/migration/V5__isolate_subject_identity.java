package db.migration;

import com.zerotrust.risk.migration.SubjectIdentityMigrationPreflight;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

import java.io.IOException;
import java.util.TreeMap;
import java.util.zip.CRC32;

/** MySQL DDL is not an atomic four-statement transaction. Restore a tested full backup on partial failure. */
public class V5__isolate_subject_identity extends BaseJavaMigration {
    @Override
    public boolean canExecuteInTransaction() { return false; }

    @Override
    public Integer getChecksum() {
        // Flyway checksum tracks the exact deployed migration + helper bytecode, including nested records.
        // Build with the pinned Java17 toolchain; source SHA-256 manifest supplies separate source integrity.
        TreeMap<String, Class<?>> classes = new TreeMap<>();
        collect(getClass(), classes);
        collect(SubjectIdentityMigrationPreflight.class, classes);
        CRC32 checksum = new CRC32();
        for (var entry : classes.entrySet()) {
            byte[] name = entry.getKey().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            checksum.update(name);
            checksum.update(0);
            try (var input = entry.getValue().getResourceAsStream("/" + entry.getKey().replace('.', '/') + ".class")) {
                if (input == null) throw new IllegalStateException("V5_CHECKSUM_CLASS_RESOURCE_MISSING");
                checksum.update(input.readAllBytes());
                checksum.update(0);
            } catch (IOException ex) { throw new IllegalStateException("V5_CHECKSUM_UNAVAILABLE", ex); }
        }
        return (int) checksum.getValue();
    }

    private static void collect(Class<?> type, TreeMap<String, Class<?>> classes) {
        classes.put(type.getName(), type);
        for (Class<?> nested : type.getDeclaredClasses()) collect(nested, classes);
    }

    @Override
    public void migrate(Context context) throws Exception {
        var connection = context.getConnection();
        var plan = SubjectIdentityMigrationPreflight.inspect(connection,
                Boolean.getBoolean(SubjectIdentityMigrationPreflight.WRITERS_QUIESCED));
        int completed = 0;
        try {
            for (String ddl : plan.statements()) {
                try (var statement = connection.createStatement()) { statement.execute(ddl); }
                SubjectIdentityMigrationPreflight.verifyAfterStatement(connection, plan, ++completed);
            }
            if (!plan.mysql()) SubjectIdentityMigrationPreflight.verifyAfterStatement(connection, plan, 0);
        } catch (Exception ex) {
            // Do not rollback, reverse collation, clean or repair: MySQL may already have committed DDL.
            throw new IllegalStateException("V5_STOP_PARTIAL_MIGRATION after " + completed
                    + " acknowledged statements; failed DDL may also have committed; keep writers stopped and restore approved consistent DB+Flyway backup; no automatic repair", ex);
        }
    }
}
