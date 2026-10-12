package com.zerotrust.zerotrust.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.zerotrust.config.KeycloakAdminProperties;
import com.zerotrust.zerotrust.identity.model.CreateIdentityUserCommand;
import com.zerotrust.zerotrust.model.request.CreateStudentRequestDTO;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class CredentialExposureTest {
    private static final String TEST_SECRET = "test-only-sensitive-value";

    @Test
    void studentPasswordIsAcceptedButExcludedFromJsonAndDiagnosticOutput() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        CreateStudentRequestDTO request = mapper.readValue(
                "{\"username\":\"student\",\"password\":\"" + TEST_SECRET + "\"}",
                CreateStudentRequestDTO.class);

        assertThat(request.getPassword()).isEqualTo(TEST_SECRET);
        assertThat(request.toString()).doesNotContain(TEST_SECRET);
        assertThat(mapper.readTree(mapper.writeValueAsString(request)).has("password")).isFalse();
    }

    @Test
    void identityCommandKeepsPasswordAccessibleButExcludesItFromDiagnosticOutput() {
        CreateIdentityUserCommand command = new CreateIdentityUserCommand(
                "student", TEST_SECRET, "student@example.test", "Test", "Student");

        assertThat(command.password()).isEqualTo(TEST_SECRET);
        assertThat(command.toString()).doesNotContain(TEST_SECRET);
    }

    @Test
    void adminPropertiesKeepSecretAccessibleButExcludeItFromDiagnosticOutput() {
        KeycloakAdminProperties properties = new KeycloakAdminProperties(
                "http://localhost:8180", "test-realm", "test-client", TEST_SECRET,
                Duration.ofSeconds(3), Duration.ofSeconds(5), Duration.ofSeconds(3), 10, 30);

        assertThat(properties.clientSecret()).isEqualTo(TEST_SECRET);
        assertThat(properties.toString()).doesNotContain(TEST_SECRET);
    }
}
