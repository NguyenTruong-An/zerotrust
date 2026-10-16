package com.zerotrust.risk.migration;

import db.migration.V5__isolate_subject_identity;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.migration.Context;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.sql.Connection;
import java.sql.DriverManager;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class SubjectIdentityMigrationPreflightTests {
    private static final String CAPTURED_ALICE = "pf03a-03132146-893c-4bff-9050-ee6ce4c4e915-upgrade-Alice";
    private static final String CAPTURED_LEGACY = "pf03a-03132146-893c-4bff-9050-ee6ce4c4e915-upgrade-trusted-legacy";
    private static final String CAPTURED_OPERATION = "34891fef-199a-4537-a05e-5942c4a9d450";

    // Exact rows from execution/upgrade-fixture-diagnosis.json, checked against after-snapshot.json.
    // The historical native full-hash assertion passed before the index-selection failure.
    private Map<String,List<Map<String,String>>> capturedUpgradeRows() {
        var data = empty();
        data.get("subject_device_trust").add(row("generation","0","subject_id",CAPTURED_LEGACY,"pending_operation_id",null));
        data.get("subject_device_trust").add(row("generation","1","subject_id",CAPTURED_ALICE,"pending_operation_id",CAPTURED_OPERATION));
        data.get("device_trust_revocations").add(row("generation","1","revoked_at","2026-10-16 00:00:00.123456",
                "subject_id",CAPTURED_ALICE,"completed_at",null,"operation_id",CAPTURED_OPERATION,"requested_by","Admin","revoked_count","1"));
        return data;
    }
    private Map<String,Map<String,String>> upgradeRows(Map<String,List<Map<String,String>>> data) {
        return SubjectIdentityMigrationMySqlTests.upgradeFixtureRows(data,CAPTURED_ALICE,CAPTURED_LEGACY,CAPTURED_OPERATION);
    }

    @Test void capturedUpgradeOrderReproducesOldIndexFailureAndExactSubjectSelectionPasses() {
        var data = capturedUpgradeRows();
        assertThat(data.get("subject_device_trust").get(0).get("subject_id")).isEqualTo(CAPTURED_LEGACY);
        assertThatThrownBy(() -> assertThat(data.get("subject_device_trust").get(0).get("pending_operation_id"))
                .isEqualTo(CAPTURED_OPERATION)).isInstanceOf(AssertionError.class);
        var selected = upgradeRows(data);
        assertThat(selected.get("Alice").get("subject_id")).isEqualTo(CAPTURED_ALICE);
        assertThat(selected.get("Alice").get("pending_operation_id")).isEqualTo(CAPTURED_OPERATION);
        assertThat(selected.get("trusted-legacy").get("generation")).isEqualTo("0");
        assertThat(selected.get("trusted-legacy").get("pending_operation_id")).isNull();
    }
    @Test void capturedUpgradeExactOwnerComparisonIsIndependentOfSnapshotOrder() {
        var before = capturedUpgradeRows(); var after = capturedUpgradeRows();
        java.util.Collections.reverse(after.get("subject_device_trust"));
        assertThat(upgradeRows(after)).isEqualTo(upgradeRows(before));
    }
    @Test void upgradeSelectionRejectsMissingCaseAliasedAndDuplicateExactAlice() {
        var missing = capturedUpgradeRows();
        missing.get("subject_device_trust").removeIf(r -> CAPTURED_ALICE.equals(r.get("subject_id")));
        assertThatThrownBy(() -> upgradeRows(missing)).isInstanceOf(AssertionError.class);
        var aliased = capturedUpgradeRows();
        aliased.get("subject_device_trust").stream().filter(r -> CAPTURED_ALICE.equals(r.get("subject_id")))
                .forEach(r -> r.put("subject_id",CAPTURED_ALICE.replace("Alice","alice")));
        assertThatThrownBy(() -> upgradeRows(aliased)).isInstanceOf(AssertionError.class);
        var duplicate = capturedUpgradeRows();
        duplicate.get("subject_device_trust").add(new HashMap<>(upgradeRows(duplicate).get("Alice")));
        assertThatThrownBy(() -> upgradeRows(duplicate)).isInstanceOf(AssertionError.class);
    }
    @Test void upgradeSelectionKeepsAliceGenerationAndPendingOperationRequirements() {
        for (String column : List.of("generation","pending_operation_id")) {
            var data = capturedUpgradeRows(); var selected = upgradeRows(data);
            selected.get("Alice").put(column,column.equals("generation") ? "0" : "00000000-0000-0000-0000-000000000000");
            assertThatThrownBy(() -> upgradeRows(data)).isInstanceOf(AssertionError.class);
        }
    }
    @Test void upgradeSelectionKeepsExactAuditOwnerRequesterAndPendingRequirements() {
        for (var change : Map.of("subject_id",CAPTURED_ALICE.replace("Alice","alice"),"requested_by","admin",
                "operation_id","00000000-0000-0000-0000-000000000000","generation","0","revoked_count","0",
                "completed_at","2026-10-16 00:01:00.123456").entrySet()) {
            var data = capturedUpgradeRows();
            upgradeRows(data).get("audit").put(change.getKey(),change.getValue());
            assertThatThrownBy(() -> upgradeRows(data)).isInstanceOf(AssertionError.class);
        }
    }
    @Test void upgradeSelectionKeepsLegacyGenerationZeroAndNullPendingRequirements() {
        for (String column : List.of("generation","pending_operation_id")) {
            var data = capturedUpgradeRows();
            upgradeRows(data).get("trusted-legacy").put(column,column.equals("generation") ? "1" : CAPTURED_OPERATION);
            assertThatThrownBy(() -> upgradeRows(data)).isInstanceOf(AssertionError.class);
        }
    }
    @Test void upgradeComparisonRejectsChangedAuditValueEvenWithSameOwnerAndOperation() {
        var before = capturedUpgradeRows(); var after = capturedUpgradeRows();
        upgradeRows(after).get("audit").put("revoked_at","2026-10-16 00:00:00.123457");
        assertThatThrownBy(() -> assertThat(upgradeRows(after)).isEqualTo(upgradeRows(before))).isInstanceOf(AssertionError.class);
    }

    private String url() { return "jdbc:h2:mem:v5_" + UUID.randomUUID() + ";MODE=MySQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1"; }
    private Flyway flyway(String url, String target) {
        return Flyway.configure().dataSource(url, "sa", "").locations("classpath:db/migration").target(target).load();
    }
    private Map<String, List<Map<String, String>>> empty() {
        Map<String, List<Map<String, String>>> data = new LinkedHashMap<>();
        SubjectIdentityMigrationPreflight.TABLES.forEach(t -> data.put(t, new ArrayList<>()));
        return data;
    }
    private Map<String, String> row(String... pairs) {
        Map<String, String> row = new HashMap<>();
        for (int i = 0; i < pairs.length; i += 2) row.put(pairs[i], pairs[i + 1]);
        return row;
    }
    private Map<String, List<Map<String, String>>> pending() {
        var data = empty(); String operation = UUID.randomUUID().toString();
        data.get("subject_device_trust").add(row("subject_id","f:provider:Alice", "generation","1", "pending_operation_id",operation));
        data.get("device_trust_revocations").add(row("subject_id","f:provider:Alice", "generation","1", "operation_id",operation,
                "requested_by","Admin", "revoked_count","0", "revoked_at","2026-10-16 00:00:00.123456", "completed_at",null));
        return data;
    }

    @Test void oldComparatorCollisionRejectsEvenIfEachRawOwnerLooksRecoverable() {
        var data = pending();
        data.get("subject_device_trust").add(row("subject_id","f:provider:alice", "generation","0", "pending_operation_id",null));
        assertThatThrownBy(() -> SubjectIdentityMigrationPreflight.validateData(data, List.of(Set.of("f:provider:Alice", "f:provider:alice")))).hasMessageContaining("AMBIGUOUS_SQL_IDENTITY_COLLISION");
    }
    @Test void rejectsUnnormalizedHistoricalSubjectRatherThanMergingState() {
        var data = empty();data.get("subject_device_trust").add(row("subject_id"," Alice ","generation","0"));
        assertThatThrownBy(() -> SubjectIdentityMigrationPreflight.validateData(data,List.of())).hasMessageContaining("NON_NORMALIZED");
    }
    @Test void preservesValidPendingWithoutReconciliation() {
        var data = pending();var original = data.toString();
        assertThatCode(() -> SubjectIdentityMigrationPreflight.validateData(data,List.of())).doesNotThrowAnyException();
        assertThat(data.toString()).isEqualTo(original);
    }
    @Test void rejectsPendingBoundToDifferentExactSubject() {
        var data = pending();data.get("device_trust_revocations").get(0).put("subject_id","f:provider:alice");
        data.get("subject_device_trust").add(row("subject_id","f:provider:alice","generation","1"));
        assertThatThrownBy(() -> SubjectIdentityMigrationPreflight.validateData(data,List.of())).hasMessageContaining("V5_");
    }
    @Test void rejectsPendingGenerationMismatch() {
        var data = pending();data.get("subject_device_trust").get(0).put("generation","2");
        assertThatThrownBy(() -> SubjectIdentityMigrationPreflight.validateData(data,List.of())).hasMessageContaining("UNEXPLAINED_GENERATION");
    }
    @Test void rejectsAlreadyCompletedPending() {
        var data = pending();data.get("device_trust_revocations").get(0).put("completed_at","2026-10-16 00:01:00");
        assertThatThrownBy(() -> SubjectIdentityMigrationPreflight.validateData(data,List.of())).hasMessageContaining("UNSAFE_PENDING");
    }
    @Test void rejectsMissingAuditInsteadOfClearingPending() {
        var data = pending();data.get("device_trust_revocations").clear();
        assertThatThrownBy(() -> SubjectIdentityMigrationPreflight.validateData(data,List.of())).hasMessageContaining("UNEXPLAINED_GENERATION");
    }
    @Test void rejectsDuplicateAuditGenerationAndLostPendingProvenance() {
        var data = pending();data.get("subject_device_trust").get(0).put("pending_operation_id",null);
        assertThatThrownBy(() -> SubjectIdentityMigrationPreflight.validateData(data,List.of())).hasMessageContaining("LATEST_AUDIT_WITHOUT_PENDING");
        var duplicate = new HashMap<>(data.get("device_trust_revocations").get(0));duplicate.put("operation_id",UUID.randomUUID().toString());
        data.get("device_trust_revocations").add(duplicate);
        assertThatThrownBy(() -> SubjectIdentityMigrationPreflight.validateData(data,List.of())).hasMessageContaining("AMBIGUOUS_AUDIT_GENERATION");
    }
    @Test void rejectsLegacyDeviceWithoutStateButAllowsSuccessOnlySubject() {
        var data = empty();data.get("known_devices").add(row("subject_id","Alice","device_fingerprint_hash","a".repeat(64)));
        assertThatThrownBy(() -> SubjectIdentityMigrationPreflight.validateData(data,List.of())).hasMessageContaining("UNRESOLVED_LEGACY_DEVICE_STATE");
        data.get("known_devices").clear();data.get("authentication_success_events").add(row("subject_id","Alice","client_id","Client"));
        assertThatCode(() -> SubjectIdentityMigrationPreflight.validateData(data,List.of())).doesNotThrowAnyException();
    }
    @Test void rejectsUnreviewedClientNormalizationAndNoncanonicalOperation() {
        var data = empty();data.get("authentication_success_events").add(row("subject_id","Alice","client_id","Client "));
        assertThatThrownBy(() -> SubjectIdentityMigrationPreflight.validateData(data,List.of())).hasMessageContaining("CLIENT_IDENTITY");
        var invalid = pending();invalid.get("device_trust_revocations").get(0).put("operation_id","bad-operation");
        assertThatThrownBy(() -> SubjectIdentityMigrationPreflight.validateData(invalid,List.of())).hasMessageContaining("INVALID_OPERATION_UUID");
    }
    @Test void rejectsMysqlBeforeAnyStatementWithoutExplicitQuiescence() throws Exception {
        Connection connection = mock(Connection.class);var metadata = mock(java.sql.DatabaseMetaData.class);
        when(connection.getMetaData()).thenReturn(metadata);when(metadata.getDatabaseProductName()).thenReturn("MySQL");
        when(metadata.getDatabaseProductVersion()).thenReturn("8.0.46");
        Context context = mock(Context.class);when(context.getConnection()).thenReturn(connection);
        String old = System.getProperty(SubjectIdentityMigrationPreflight.WRITERS_QUIESCED);
        try {
            System.clearProperty(SubjectIdentityMigrationPreflight.WRITERS_QUIESCED);
            assertThatThrownBy(() -> new V5__isolate_subject_identity().migrate(context)).hasMessageContaining("WRITERS_NOT_QUIESCED");
            verify(connection,never()).createStatement();verify(connection,never()).prepareStatement(anyString());
        } finally { if(old != null)System.setProperty(SubjectIdentityMigrationPreflight.WRITERS_QUIESCED,old); }
    }
    @Test void h2UpgradeAndFlywayValidatePreserveAllRowValuesAndChecksums() throws Exception {
        String url = url();flyway(url,"4").migrate();
        try (var c = DriverManager.getConnection(url,"sa","")) {
            c.createStatement().executeUpdate("INSERT INTO subject_device_trust(subject_id,generation) VALUES('Alice',0),('alice',0)");
            var before = SubjectIdentityMigrationPreflight.snapshot(c);
            var plan = SubjectIdentityMigrationPreflight.inspect(c,false);
            assertThat(plan.mysql()).isFalse();assertThat(plan.statements()).isEmpty();
            var result = flyway(url,"latest").migrate();assertThat(result.migrationsExecuted).isEqualTo(1);
            assertThat(SubjectIdentityMigrationPreflight.snapshot(c).sha256()).isEqualTo(before.sha256());
            flyway(url,"latest").validate();
            assertThat(new V5__isolate_subject_identity().getChecksum()).isNotNull().isEqualTo(new V5__isolate_subject_identity().getChecksum());
            assertThat(new V5__isolate_subject_identity().canExecuteInTransaction()).isFalse();
        }
    }
    @Test void invalidH2UpgradeRejectsBeforeMigrationAndLeavesOriginalRowsAndSchema() throws Exception {
        String url = url();flyway(url,"4").migrate();
        try (var c = DriverManager.getConnection(url,"sa","")) {
            c.createStatement().executeUpdate("INSERT INTO subject_device_trust(subject_id,generation) VALUES(' Alice ',0)");
            var before = SubjectIdentityMigrationPreflight.snapshot(c);
            assertThatThrownBy(() -> flyway(url,"latest").migrate()).hasStackTraceContaining("NON_NORMALIZED");
            assertThat(SubjectIdentityMigrationPreflight.snapshot(c).sha256()).isEqualTo(before.sha256());
            // Application data/schema are unchanged; a nontransactional Flyway failure may record a failed history row.
            try(var columns=c.getMetaData().getColumns(null,null,"subject_device_trust","subject_id")) {
                assertThat(columns.next()).isTrue();assertThat(columns.getInt("COLUMN_SIZE")).isEqualTo(255);
            }
        }
    }
    @Test void unrecognizedColumnsAndVarcharIgnorecaseFailBeforeProceeding() throws Exception {
        String url=url();flyway(url,"4").migrate();
        try(var c=DriverManager.getConnection(url,"sa","")) {
            c.createStatement().execute("ALTER TABLE subject_device_trust ALTER COLUMN subject_id VARCHAR_IGNORECASE(255) NOT NULL");
            assertThatThrownBy(()->SubjectIdentityMigrationPreflight.inspect(c,false)).hasMessageContaining("IDENTITY_TYPE");
        }
        url=url();flyway(url,"4").migrate();
        try(var c=DriverManager.getConnection(url,"sa","")) {
            c.createStatement().execute("ALTER TABLE subject_device_trust ADD COLUMN unknown_state INT");
            assertThatThrownBy(()->SubjectIdentityMigrationPreflight.inspect(c,false)).hasMessageContaining("COLUMN_LAYOUT");
        }
    }

    // Exact bytes captured from MySQL8.0.46 CHECK_CONSTRAINTS.CHECK_CLAUSE after the native failure.
    @Test void acceptsExactCapturedMySql8046StatusMetadata() {
        String clause = new String(java.util.HexFormat.of().parseHex("28607374617475736020696E20285F757466386D62345C2750454E44494E475C272C5F757466386D62345C27545255535445445C272C5F757466386D62345C275245564F4B45445C272929"), java.nio.charset.StandardCharsets.UTF_8);
        assertThatCode(() -> SubjectIdentityMigrationPreflight.validateStatusCheckPolicy(clause)).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @MethodSource("reviewedStatusPolicyRepresentations")
    void acceptsOnlyReviewedStatusPolicyRepresentations(String expression) {
        assertThatCode(() -> SubjectIdentityMigrationPreflight.validateStatusCheckPolicy(expression)).doesNotThrowAnyException();
    }

    static Stream<String> reviewedStatusPolicyRepresentations() {
        return Stream.of(
                "status IN ('PENDING', 'TRUSTED', 'REVOKED')",
                "(`status` in (_utf8mb4'PENDING',_utf8mb4'TRUSTED',_utf8mb4'REVOKED'))",
                "((`status` in (_utf8mb4\\'PENDING\\',_utf8mb4\\'TRUSTED\\',_utf8mb4\\'REVOKED\\')))",
                " \n ( ( STATUS\tIn\n( 'PENDING' , 'TRUSTED' , 'REVOKED' ) ) ) \t",
                "status in (_UTF8MB4'PENDING',_utf8mb4 'TRUSTED','REVOKED')",
                "status IN (\\'PENDING\\',\\'TRUSTED\\',\\'REVOKED\\')");
    }

    @ParameterizedTest
    @MethodSource("unreviewedStatusPolicies")
    void rejectsUnknownModifiedOrMalformedStatusPolicies(String expression) {
        assertThatThrownBy(() -> SubjectIdentityMigrationPreflight.validateStatusCheckPolicy(expression))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("UNREVIEWED_STATUS_CHECK_POLICY");
    }

    static Stream<String> unreviewedStatusPolicies() {
        String policy = "status IN ('PENDING','TRUSTED','REVOKED')";
        return Stream.concat(Stream.of((String) null, "", " ", "(".repeat(4097)), Stream.of(
                "1=1", "other_status IN ('PENDING','TRUSTED','REVOKED')",
                "statusin('PENDING','TRUSTED','REVOKED')", "`status IN ('PENDING','TRUSTED','REVOKED')",
                "status` IN ('PENDING','TRUSTED','REVOKED')", "status NOT IN ('PENDING','TRUSTED','REVOKED')",
                policy + " OR 1=1", policy + " AND generation=0", "(" + policy + ") OR " + policy,
                policy + ";", policy + " -- comment", policy + " # comment", "/*comment*/" + policy,
                policy.replace(" IN ", " /*comment*/ IN "), "CHECK (" + policy + ")",
                policy.replace("PENDING", "pending"), policy.replace("REVOKED", "EXPIRED"),
                "status IN ('PENDING','TRUSTED')", "status IN ('PENDING','TRUSTED','REVOKED','EXPIRED')",
                "status IN ('PENDING','TRUSTED','TRUSTED')", "status IN ('PENDING',NULL,'REVOKED')",
                "status IN (_latin1'PENDING','TRUSTED','REVOKED')", "status IN (_binary'PENDING','TRUSTED','REVOKED')",
                "status IN (_utf8mb4x'PENDING','TRUSTED','REVOKED')", "status IN (N'PENDING','TRUSTED','REVOKED')",
                "status IN ('PENDING' COLLATE utf8mb4_0900_bin,'TRUSTED','REVOKED')",
                "status IN (\"PENDING\",'TRUSTED','REVOKED')", "status IN ('PENDING','TRUSTED','REVOKED') COLLATE x",
                "status IN ('PENDING\\','TRUSTED','REVOKED')", "status IN (\\'PENDING','TRUSTED','REVOKED')",
                "status IN ('PENDING',\\'TRUSTED\\','REVOKED')", "status IN (\\'PENDING\\',\\'TRUSTED\\','REVOKED')",
                "status IN ('PEND\\ING','TRUSTED','REVOKED')", "status IN ('PENDING\\'OR1=1','TRUSTED','REVOKED')",
                "status IN (\\\\'PENDING\\\\',\\\\'TRUSTED\\\\',\\\\'REVOKED\\\\')",
                "status IN ('PENDING' + '', 'TRUSTED', 'REVOKED')", "status IN ('PENDING','TRUSTED','REVOKED',)",
                "(" + policy, policy + ")", "((" + policy + ")", "(" + policy + "))",
                policy.replace("PENDING", "PEN(DING)"), policy.replace("PENDING", "PENDING "),
                "status IN (_utf8mb4\\'PENDING\\',_utf8mb4\\'TRUSTED\\',_utf8mb4\\'REVOKED)",
                policy + "\u0000"));
    }
}
