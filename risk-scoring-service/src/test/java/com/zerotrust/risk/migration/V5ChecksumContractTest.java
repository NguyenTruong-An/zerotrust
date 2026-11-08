package com.zerotrust.risk.migration;

import db.migration.V5__isolate_subject_identity;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class V5ChecksumContractTest {
    @Test
    void preservesTheAppliedMigrationBytecodeChecksumAcrossDependencyAndToolchainUpdates() {
        // Observed before PD-02-02 with the pinned build, not derived from the code under test.
        // Do not change this value to repair an applied Flyway migration; review that contract separately.
        assertThat(new V5__isolate_subject_identity().getChecksum())
                .as("V5 applied checksum: Java 17 release/debug/parameters and UTF-8 source encoding")
                .isEqualTo(661092940);
    }
}
