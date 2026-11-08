package com.zerotrust.zerotrust.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class PublicDemoSchoolDatabaseVerifierTest {
    private static final String SCHEMA = "pd_production_school";

    private static Set<String> selectGrants() {
        Set<String> result = new HashSet<>();
        for (String table : Set.of("users", "students", "student_classes", "subjects", "scores")) {
            result.add(PublicDemoStartupConfigurationTest.MockDatabase.grant(table));
        }
        return result;
    }

    @Test
    void acceptsExactlyFiveTableSelectGrantsAndHarmlessUsage() {
        Set<String> grants = selectGrants();
        grants.add("GRANT USAGE ON *.* TO 'pd_production_school_runtime'@'%'");
        assertThatCode(() -> PublicDemoSchoolDatabaseVerifier.verifyGrants(SCHEMA, grants)).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "GRANT ALL PRIVILEGES ON *.* TO 'runtime'@'%'",
            "GRANT INSERT, UPDATE, DELETE ON `pd_production_school`.`scores` TO 'runtime'@'%'",
            "GRANT CREATE ON `pd_production_school`.* TO 'runtime'@'%'",
            "GRANT SELECT ON `pd_production_school`.* TO 'runtime'@'%'",
            "GRANT SELECT ON `vip_pro`.`scores` TO 'runtime'@'%'",
            "GRANT SELECT ON `pd_production_school`.`scores` TO 'runtime'@'%' WITH GRANT OPTION",
            "GRANT SELECT ON `pd_production_school`.`other_table` TO 'runtime'@'%'",
            "GRANT 'writable_role'@'%' TO 'runtime'@'%'",
            "GRANT PROXY ON 'root'@'localhost' TO 'runtime'@'%'",
            "GRANT SYSTEM_USER ON *.* TO 'runtime'@'%'",
            "malformed-or-new-server-format"})
    void rejectsAdditionalPrivilegesRolesAndUnknownGrantSyntax(String extraGrant) {
        Set<String> grants = selectGrants(); grants.add(extraGrant);
        assertThatThrownBy(() -> PublicDemoSchoolDatabaseVerifier.verifyGrants(SCHEMA, grants))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void missingSelectPrivilegeFailsInsteadOfStartingBrokenReadApi() {
        Set<String> grants = selectGrants(); grants.remove(PublicDemoStartupConfigurationTest.MockDatabase.grant("scores"));
        assertThatThrownBy(() -> PublicDemoSchoolDatabaseVerifier.verifyGrants(SCHEMA, grants))
                .hasMessageContaining("incomplete");
    }

    @Test
    void queryFailureIsSanitizedAndNeverFallsBackToAssumingReadOnly() throws Exception {
        DataSource source = mock(DataSource.class);
        when(source.getConnection()).thenThrow(new SQLException("jdbc:mysql://root:synthetic-password@lab/secret"));
        assertThatThrownBy(() -> new PublicDemoSchoolDatabaseVerifier(source, SCHEMA).afterSingletonsInstantiated())
                .hasMessageContaining("details redacted").hasNoCause()
                .hasMessageNotContaining("synthetic-password");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "vip_pro", "h2", "no-tls", "wrong-user"})
    void wrongCatalogEngineOrMissingTlsFailsClosed(String scenario) throws Exception {
        DataSource source = mock(DataSource.class);
        Connection connection = mock(Connection.class);
        DatabaseMetaData metadata = mock(DatabaseMetaData.class);
        Statement statement = mock(Statement.class);
        ResultSet tls = mock(ResultSet.class);
        when(source.getConnection()).thenReturn(connection);
        when(connection.getCatalog()).thenReturn(Set.of("h2", "no-tls", "wrong-user").contains(scenario) ? SCHEMA : scenario);
        when(connection.getMetaData()).thenReturn(metadata);
        when(metadata.getDatabaseProductName()).thenReturn(scenario.equals("h2") ? "H2" : "MySQL");
        when(connection.createStatement()).thenReturn(statement);
        ResultSet account = mock(ResultSet.class);
        when(account.next()).thenReturn(true);
        when(account.getString(1)).thenReturn(scenario.equals("wrong-user") ? "anonymous@%" : SCHEMA + "_runtime@%");
        when(statement.executeQuery("SELECT CURRENT_USER()")).thenReturn(account);
        when(statement.executeQuery("SHOW SESSION STATUS LIKE 'Ssl_cipher'")).thenReturn(tls);
        when(tls.next()).thenReturn(true);
        when(tls.getString(2)).thenReturn("");
        assertThatThrownBy(() -> new PublicDemoSchoolDatabaseVerifier(source, SCHEMA).afterSingletonsInstantiated())
                .hasMessageContaining("details redacted");
        verify(connection).close();
        verify(statement, never()).executeUpdate(anyString());
    }
}
