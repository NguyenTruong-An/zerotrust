package com.zerotrust.risk.migration;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;

/** Immutable V5 contract. Do not change applied migration behavior; add a new migration instead. */
public final class SubjectIdentityMigrationPreflight {
    public static final String WRITERS_QUIESCED = "zerotrust.migration.subject-identity.writers-quiesced";
    public static final String EXACT = "utf8mb4_0900_bin";
    public static final List<String> TABLES = List.of("subject_device_trust", "known_devices",
            "device_trust_revocations", "authentication_success_events");
    public static final List<String> DDL = List.of(
            alter("subject_device_trust", false), alter("known_devices", false),
            alter("device_trust_revocations", false), alter("authentication_success_events", true));
    private static final Map<String, Set<String>> COLUMNS = Map.of(
            "subject_device_trust", Set.of("subject_id", "generation", "pending_operation_id"),
            "known_devices", Set.of("id", "subject_id", "device_fingerprint_hash", "status", "first_seen_at",
                    "last_seen_at", "trusted_at", "revoked_at", "version", "revocation_reason"),
            "device_trust_revocations", Set.of("operation_id", "subject_id", "requested_by", "generation",
                    "revoked_count", "revoked_at", "completed_at"),
            "authentication_success_events", Set.of("id", "event_id", "subject_id", "client_id", "authenticated_at", "recorded_at"));

    private SubjectIdentityMigrationPreflight() {}

    private static String alter(String table, boolean client) {
        return "ALTER TABLE " + table + " MODIFY COLUMN subject_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE "
                + EXACT + " NOT NULL" + (client ? ", MODIFY COLUMN client_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE "
                + EXACT + " NOT NULL" : "") + ", ALGORITHM=COPY, LOCK=EXCLUSIVE";
    }

    public record Snapshot(Map<String, List<Map<String, String>>> tables, String sha256) {}
    public record Plan(boolean mysql, Snapshot baseline, List<String> statements) {}

    public static Plan inspect(Connection connection, boolean writersQuiesced) throws SQLException {
        String vendor = connection.getMetaData().getDatabaseProductName();
        boolean mysql = "MySQL".equals(vendor);
        require(mysql || "H2".equals(vendor), "UNSUPPORTED_VENDOR");
        if (mysql) {
            require(connection.getMetaData().getDatabaseProductVersion().matches("8\\.0\\.46(?:[-+].*)?"), "UNREVIEWED_MYSQL_VERSION");
            require(writersQuiesced, "WRITERS_NOT_QUIESCED");
            validateMySqlLayout(connection, false);
        } else {
            // H2 validation only. No MySQL DDL is executed on the unit-test database.
            for (String[] pair : List.of(new String[]{"A", "a"}, new String[]{"café", "cafe"}, new String[]{"é", "e\u0301"})) {
                try (var statement = connection.prepareStatement("SELECT CASE WHEN CAST(? AS VARCHAR) = CAST(? AS VARCHAR) THEN 0 ELSE 1 END")) {
                    statement.setString(1, pair[0]); statement.setString(2, pair[1]);
                    try (var rows = statement.executeQuery()) { require(rows.next() && rows.getInt(1) == 1, "H2_NOT_EXACT"); }
                }
            }
            validateColumns(connection);
        }
        Snapshot snapshot = snapshot(connection);
        List<Set<String>> aliases = new ArrayList<>();
        if (mysql) {
            String union = String.join(" UNION ALL ", TABLES.stream().map(t -> "SELECT subject_id FROM " + t).toList());
            // HEX makes the DISTINCT count independent of the old text comparator.
            for (Map<String, String> row : query(connection, "SELECT subject_id FROM (" + union
                    + ") identities GROUP BY subject_id HAVING COUNT(DISTINCT HEX(subject_id)) > 1")) {
                Set<String> group = new HashSet<>();
                try (var statement = connection.prepareStatement("SELECT subject_id FROM (" + union + ") identities WHERE subject_id = ?")) {
                    statement.setString(1, row.get("subject_id"));
                    try (ResultSet values = statement.executeQuery()) { while (values.next()) group.add(values.getString(1)); }
                }
                aliases.add(group);
            }
        }
        validateData(snapshot.tables(), aliases);
        return new Plan(mysql, snapshot, mysql ? DDL : List.of());
    }

    /** Pure validation also used by non-native tests; alias sets must come from the actual old SQL comparator. */
    public static void validateData(Map<String, List<Map<String, String>>> tables, List<Set<String>> aliases) {
        require(tables.keySet().equals(new HashSet<>(TABLES)), "INCOMPLETE_APPLICATION_SNAPSHOT");
        require(aliases.isEmpty(), "AMBIGUOUS_SQL_IDENTITY_COLLISION");
        Map<String, Map<String, String>> states = new HashMap<>();
        Map<String, Map<String, String>> audits = new HashMap<>();
        for (String table : TABLES) {
            for (Map<String, String> row : tables.get(table)) {
                String subject = row.get("subject_id");
                require(validText(subject) && subject.equals(subject.trim()), "NON_NORMALIZED_OR_INVALID_SUBJECT");
            }
        }
        for (Map<String, String> state : tables.get("subject_device_trust")) {
            require(states.put(state.get("subject_id"), state) == null, "DUPLICATE_EXACT_STATE");
            require(number(state, "generation") >= 0, "INVALID_GENERATION");
            if (state.get("pending_operation_id") != null) canonicalUuid(state.get("pending_operation_id"));
        }
        Map<String, Long> maximumAuditGeneration = new HashMap<>();
        Map<String, Set<Long>> auditGenerations = new HashMap<>();
        for (Map<String, String> audit : tables.get("device_trust_revocations")) {
            canonicalUuid(audit.get("operation_id"));
            require(audits.put(audit.get("operation_id"), audit) == null, "DUPLICATE_OPERATION");
            require(validText(audit.get("requested_by")), "INVALID_AUDIT_ACTOR");
            Map<String, String> state = states.get(audit.get("subject_id"));
            require(state != null, "MISSING_EXACT_AUDIT_STATE");
            long generation = number(audit, "generation");
            require(generation > 0 && generation <= number(state, "generation")
                    && number(audit, "revoked_count") >= 0 && audit.get("revoked_at") != null, "UNSAFE_AUDIT_GENERATION");
            require(auditGenerations.computeIfAbsent(audit.get("subject_id"), ignored -> new HashSet<>()).add(generation), "AMBIGUOUS_AUDIT_GENERATION");
            maximumAuditGeneration.merge(audit.get("subject_id"), generation, Math::max);
        }
        for (Map<String, String> state : states.values()) {
            require(number(state, "generation") == maximumAuditGeneration.getOrDefault(state.get("subject_id"), 0L), "UNEXPLAINED_GENERATION");
            String operation = state.get("pending_operation_id");
            if (operation != null) {
                Map<String, String> audit = audits.get(operation);
                require(audit != null && state.get("subject_id").equals(audit.get("subject_id"))
                        && state.get("generation").equals(audit.get("generation"))
                        && audit.get("completed_at") == null, "UNSAFE_PENDING_OWNER_OR_GENERATION");
            } else {
                for (Map<String, String> audit : audits.values()) {
                    require(!state.get("subject_id").equals(audit.get("subject_id"))
                            || !state.get("generation").equals(audit.get("generation"))
                            || audit.get("completed_at") != null, "LATEST_AUDIT_WITHOUT_PENDING_OR_COMPLETION");
                }
            }
        }
        for (Map<String, String> device : tables.get("known_devices")) {
            require(states.containsKey(device.get("subject_id")), "UNRESOLVED_LEGACY_DEVICE_STATE");
            require(device.get("device_fingerprint_hash") != null
                    && device.get("device_fingerprint_hash").matches("[0-9a-f]{64}"), "INVALID_DEVICE_DIGEST");
        }
        // Success-only subjects need no device-trust state: history is not a grant of trust.
        for (Map<String, String> event : tables.get("authentication_success_events")) {
            String client = event.get("client_id");
            require(validText(client) && client.equals(client.trim()), "UNRESOLVED_CLIENT_IDENTITY");
        }
    }

    public static void verifyAfterStatement(Connection connection, Plan plan, int completedStatements) throws SQLException {
        require(snapshot(connection).sha256().equals(plan.baseline().sha256()), "ROW_VALUES_CHANGED_STOP_AND_RESTORE");
        if (plan.mysql()) {
            for (int i = 0; i < completedStatements; i++) {
                for (Map<String, String> column : query(connection, "SELECT column_name, collation_name FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='" + TABLES.get(i) + "'")) {
                    if ("subject_id".equals(column.get("column_name")) || (i == 3 && "client_id".equals(column.get("column_name")))) {
                        require(EXACT.equals(column.get("collation_name")), "INCOMPLETE_COLUMN_MIGRATION");
                    }
                }
            }
            if (completedStatements == DDL.size()) validateMySqlLayout(connection, true);
        }
    }

    public static Snapshot snapshot(Connection connection) throws SQLException {
        Map<String, List<Map<String, String>>> tables = new LinkedHashMap<>();
        StringBuilder canonical = new StringBuilder();
        for (String table : TABLES) {
            List<Map<String, String>> rows = query(connection, "SELECT * FROM " + table);
            rows.sort(Comparator.comparing(SubjectIdentityMigrationPreflight::encode));
            tables.put(table, rows);
            canonical.append(table).append(':').append(rows.size()).append(':');
            rows.forEach(row -> canonical.append(encode(row)));
        }
        try {
            return new Snapshot(tables, HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(canonical.toString().getBytes(StandardCharsets.UTF_8))));
        } catch (java.security.NoSuchAlgorithmException ex) { throw new IllegalStateException(ex); }
    }

    private static String encode(Map<String, String> row) {
        StringBuilder result = new StringBuilder();
        new TreeMap<>(row).forEach((key, value) -> {
            result.append(key.length()).append(':').append(key);
            if (value == null) result.append("N;");
            else result.append('V').append(value.length()).append(':').append(value);
        });
        return result.toString();
    }

    private static void validateColumns(Connection connection) throws SQLException {
        for (String table : TABLES) {
            Set<String> actual = new HashSet<>();
            try (var statement = connection.createStatement(); ResultSet rows = statement.executeQuery("SELECT * FROM " + table + " WHERE 1=0")) {
                var metadata = rows.getMetaData();
                for (int i = 1; i <= metadata.getColumnCount(); i++) {
                    String column = metadata.getColumnName(i).toLowerCase(java.util.Locale.ROOT);
                    actual.add(column);
                    if (column.equals("subject_id") || (table.equals("authentication_success_events") && column.equals("client_id"))) {
                        require(metadata.getColumnType(i) == java.sql.Types.VARCHAR
                                && !metadata.getColumnTypeName(i).toUpperCase(java.util.Locale.ROOT).contains("IGNORECASE")
                                && metadata.getPrecision(i) == 255 && metadata.isNullable(i) == java.sql.ResultSetMetaData.columnNoNulls, "UNREVIEWED_IDENTITY_TYPE");
                    }
                }
            }
            require(actual.equals(COLUMNS.get(table)), "UNREVIEWED_COLUMN_LAYOUT");
        }
    }

    private static void validateMySqlLayout(Connection connection, boolean after) throws SQLException {
        validateColumns(connection);
        require(scalar(connection, "SELECT @@innodb_page_size").equals("16384"), "UNREVIEWED_INNODB_PAGE_SIZE");
        require(scalar(connection, "SELECT COUNT(*) FROM information_schema.collations WHERE collation_name='utf8mb4_0900_bin' AND pad_attribute='NO PAD'").equals("1"), "MISSING_EXACT_NO_PAD_COLLATION");
        String expected = after ? EXACT : "utf8mb4_0900_ai_ci";
        Map<String, Map<String, String>> expectedIndices = Map.of(
                "subject_device_trust", Map.of("PRIMARY", "0:subject_id"),
                "known_devices", Map.of("PRIMARY", "0:id", "uk_known_devices_subject_fingerprint", "0:subject_id,device_fingerprint_hash", "idx_known_devices_subject_status", "1:subject_id,status", "idx_known_devices_last_seen", "1:last_seen_at"),
                "device_trust_revocations", Map.of("PRIMARY", "0:operation_id", "idx_device_revocations_subject", "1:subject_id,revoked_at"),
                "authentication_success_events", Map.of("PRIMARY", "0:id", "uk_authentication_success_events_event_id", "0:event_id", "idx_authentication_success_events_subject_time", "1:subject_id,authenticated_at", "idx_authentication_success_events_recorded_at", "1:recorded_at", "idx_authentication_success_events_subject_client_time", "1:subject_id,client_id,authenticated_at"));
        for (String table : TABLES) {
            List<Map<String, String>> options = query(connection, "SELECT engine,row_format FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='" + table + "'");
            require(options.size() == 1 && "InnoDB".equals(options.get(0).get("engine"))
                    && "Dynamic".equalsIgnoreCase(options.get(0).get("row_format")), "UNREVIEWED_TABLE_LAYOUT");
            for (Map<String, String> c : query(connection, "SELECT column_name,column_type,data_type,character_maximum_length,character_set_name,collation_name,is_nullable,column_default,extra,datetime_precision FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='" + table + "'")) {
                String name = c.get("column_name"), type = c.get("data_type");
                boolean target = name.equals("subject_id") || (table.equals("authentication_success_events") && name.equals("client_id"));
                if (target) require("varchar".equals(type) && "varchar(255)".equals(c.get("column_type")) && "255".equals(c.get("character_maximum_length"))
                        && "utf8mb4".equals(c.get("character_set_name")) && expected.equals(c.get("collation_name"))
                        && "NO".equals(c.get("is_nullable")) && c.get("column_default") == null && c.get("extra").isEmpty(), "UNREVIEWED_SUBJECT_COLUMN_OR_PARTIAL_SCHEMA");
                else validateOtherColumn(table, name, c);
            }
            Map<String, String> indices = new HashMap<>();
            for (Map<String, String> index : query(connection, "SELECT index_name,non_unique,GROUP_CONCAT(column_name ORDER BY seq_in_index) column_names,COUNT(sub_part) prefixes,MIN(index_type) index_type,MIN(collation) key_order,MAX(collation) max_order FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='" + table + "' GROUP BY index_name,non_unique")) {
                require("0".equals(index.get("prefixes")) && "BTREE".equals(index.get("index_type"))
                        && "A".equals(index.get("key_order")) && "A".equals(index.get("max_order")), "UNREVIEWED_INDEX_SHAPE");
                indices.put(index.get("index_name"), index.get("non_unique") + ":" + index.get("column_names"));
            }
            require(indices.equals(expectedIndices.get(table)), "UNREVIEWED_PK_OR_INDEX_LAYOUT");
            require(scalar(connection, "SELECT COUNT(*) FROM information_schema.key_column_usage WHERE referenced_table_name IS NOT NULL AND ((table_schema=DATABASE() AND table_name='" + table + "') OR (referenced_table_schema=DATABASE() AND referenced_table_name='" + table + "'))").equals("0"), "UNREVIEWED_FOREIGN_KEY");
            require(scalar(connection, "SELECT COUNT(*) FROM information_schema.triggers WHERE event_object_schema=DATABASE() AND event_object_table='" + table + "'").equals("0"), "UNREVIEWED_TRIGGER");
            Set<String> checks = new HashSet<>();
            for (Map<String, String> constraint : query(connection, "SELECT constraint_name FROM information_schema.table_constraints WHERE table_schema=DATABASE() AND table_name='" + table + "' AND constraint_type='CHECK'")) checks.add(constraint.get("constraint_name"));
            require(checks.equals(table.equals("known_devices") ? Set.of("ck_known_devices_status") : Set.of()), "UNREVIEWED_CHECK_CONSTRAINT");
            if (table.equals("known_devices")) {
                validateStatusCheckPolicy(scalar(connection, "SELECT check_clause FROM information_schema.check_constraints WHERE constraint_schema=DATABASE() AND constraint_name='ck_known_devices_status'"));
            }
        }
    }

    static void validateStatusCheckPolicy(String clause) {
        require(clause != null && clause.length() <= 4096, "UNREVIEWED_STATUS_CHECK_POLICY");
        String expression = clause.strip();
        // Remove only balanced parentheses enclosing the entire reviewed expression.
        // The allowed literals contain no parentheses; other literal contents still fail the grammar.
        while (expression.startsWith("(")) {
            int depth = 0, closing = -1;
            for (int i = 0; i < expression.length(); i++) {
                if (expression.charAt(i) == '(') depth++;
                else if (expression.charAt(i) == ')' && --depth == 0) { closing = i; break; }
            }
            if (closing != expression.length() - 1) break;
            expression = expression.substring(1, closing).strip();
        }
        // MySQL8.0.46 CHECK_CLAUSE escapes both literal delimiters; SHOW CREATE uses raw quotes.
        // Accept either complete representation, never strip backslashes or mix quote modes.
        for (String delimiter : List.of("'", "\\'")) {
            String quote = java.util.regex.Pattern.quote(delimiter);
            String introducer = "(?:(?i:_utf8mb4)\\s*)?";
            List<String> literals = List.of("PENDING", "TRUSTED", "REVOKED").stream()
                    .map(value -> introducer + quote + value + quote).toList();
            String grammar = "(?i:(?:status|`status`)\\s+in)\\s*\\(\\s*"
                    + String.join("\\s*,\\s*", literals) + "\\s*\\)";
            if (expression.matches(grammar)) return;
        }
        require(false, "UNREVIEWED_STATUS_CHECK_POLICY");
    }

    private static void validateOtherColumn(String table, String name, Map<String, String> c) {
        String type = c.get("data_type");
        boolean nullable = Set.of("pending_operation_id", "trusted_at", "revoked_at", "completed_at", "revocation_reason").contains(name)
                && !(table.equals("device_trust_revocations") && name.equals("revoked_at"));
        require((nullable ? "YES" : "NO").equals(c.get("is_nullable")), "UNREVIEWED_NULLABILITY");
        if (Set.of("id", "generation", "version").contains(name)) require("bigint".equals(type), "UNREVIEWED_INTEGER_TYPE");
        else if (name.equals("revoked_count")) require("int".equals(type), "UNREVIEWED_COUNT_TYPE");
        else if (name.endsWith("_at")) require("timestamp".equals(type) && "6".equals(c.get("datetime_precision")), "UNREVIEWED_TIME_TYPE");
        else {
            int length = switch (name) { case "device_fingerprint_hash" -> 64; case "status" -> 20; case "revocation_reason" -> 32; case "operation_id", "pending_operation_id" -> 36; default -> 255; };
            require((name.equals("device_fingerprint_hash") ? "char" : "varchar").equals(type)
                    && Integer.toString(length).equals(c.get("character_maximum_length"))
                    && "utf8mb4".equals(c.get("character_set_name"))
                    && "utf8mb4_0900_ai_ci".equals(c.get("collation_name")), "UNREVIEWED_NON_TARGET_TEXT_COLUMN");
        }
        require((name.equals("id") ? "auto_increment" : "").equals(c.get("extra")), "UNREVIEWED_COLUMN_EXTRA");
        String expectedType = name.endsWith("_at") ? "timestamp(6)" : Set.of("id", "generation", "version", "revoked_count").contains(name)
                ? type : type + "(" + c.get("character_maximum_length") + ")";
        require(expectedType.equals(c.get("column_type")), "UNREVIEWED_FULL_COLUMN_TYPE");
        String expectedDefault = Set.of("generation", "version").contains(name) && !table.equals("device_trust_revocations") ? "0" : null;
        require(java.util.Objects.equals(expectedDefault, c.get("column_default")), "UNREVIEWED_COLUMN_DEFAULT");
    }

    private static List<Map<String, String>> query(Connection connection, String sql) throws SQLException {
        List<Map<String, String>> result = new ArrayList<>();
        try (var statement = connection.createStatement()) {
            statement.setQueryTimeout(30);
            try (ResultSet rows = statement.executeQuery(sql)) {
                var metadata = rows.getMetaData();
                while (rows.next()) {
                    Map<String, String> row = new LinkedHashMap<>();
                    for (int i = 1; i <= metadata.getColumnCount(); i++) row.put(metadata.getColumnLabel(i).toLowerCase(java.util.Locale.ROOT), rows.getString(i));
                    result.add(row);
                }
            }
        }
        return result;
    }

    private static String scalar(Connection connection, String sql) throws SQLException { return query(connection, sql).get(0).values().iterator().next(); }
    private static boolean validText(String text) { return text != null && !text.isBlank() && text.length() <= 255 && !text.trim().isEmpty(); }
    private static long number(Map<String, String> row, String key) {
        try { return Long.parseLong(row.get(key)); } catch (RuntimeException ex) { throw new IllegalStateException("V5_INVALID_NUMERIC_STATE"); }
    }
    private static void canonicalUuid(String value) {
        try { require(UUID.fromString(value).toString().equals(value), "NON_CANONICAL_OPERATION_UUID"); }
        catch (IllegalArgumentException | NullPointerException ex) { throw new IllegalStateException("V5_INVALID_OPERATION_UUID"); }
    }
    private static void require(boolean valid, String reason) { if (!valid) throw new IllegalStateException("V5_" + reason + "; stop; no automatic reconciliation or repair"); }
}
