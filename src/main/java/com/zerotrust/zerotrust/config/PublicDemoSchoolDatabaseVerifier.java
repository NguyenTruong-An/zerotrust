package com.zerotrust.zerotrust.config;

import org.springframework.beans.factory.SmartInitializingSingleton;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/** Read-only metadata proof before application readiness; unknown grants/roles fail closed. */
public final class PublicDemoSchoolDatabaseVerifier implements SmartInitializingSingleton {
    private static final Set<String> TABLES = Set.of("users", "students", "student_classes", "subjects", "scores");
    private final DataSource dataSource;
    private final String schema;

    public PublicDemoSchoolDatabaseVerifier(DataSource dataSource, String schema) {
        this.dataSource = dataSource;
        this.schema = schema;
    }

    @Override
    public void afterSingletonsInstantiated() {
        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            if (!schema.equals(connection.getCatalog()) || !"MySQL".equals(connection.getMetaData().getDatabaseProductName())) {
                throw new IllegalStateException();
            }
            try (ResultSet account = statement.executeQuery("SELECT CURRENT_USER()")) {
                if (!account.next() || account.getString(1) == null
                        || !account.getString(1).startsWith(schema + "_runtime@")) {
                    throw new IllegalStateException();
                }
            }
            try (ResultSet ssl = statement.executeQuery("SHOW SESSION STATUS LIKE 'Ssl_cipher'")) {
                if (!ssl.next() || ssl.getString(2) == null || ssl.getString(2).isBlank()) throw new IllegalStateException();
            }
            Set<String> grants = new HashSet<>();
            try (ResultSet rows = statement.executeQuery("SHOW GRANTS FOR CURRENT_USER")) {
                while (rows.next()) grants.add(rows.getString(1));
            }
            verifyGrants(schema, grants);
        } catch (Exception ignored) {
            // SQL exceptions can embed JDBC URLs/passwords or GRANT account clauses.
            throw new IllegalStateException("Public Demo School database TLS/grants verification failed (details redacted)");
        }
    }

    static void verifyGrants(String schema, Set<String> grants) {
        Set<String> selected = new HashSet<>();
        for (String grant : grants) {
            if (grant.matches("GRANT USAGE ON \\*\\.\\* TO [`'][^`']+[`']@[`'][^`']+[`']")) continue;
            boolean matched = false;
            for (String table : TABLES) {
                String target = Pattern.quote("`" + schema + "`.`" + table + "`");
                if (grant.matches("GRANT SELECT ON " + target + " TO [`'][^`']+[`']@[`'][^`']+[`']")) {
                    selected.add(table); matched = true; break;
                }
            }
            if (!matched) throw new IllegalStateException("School account must have only the five table SELECT grants");
        }
        if (!selected.equals(TABLES)) throw new IllegalStateException("School SELECT grants are incomplete");
    }
}
