package com.zerotrust.zerotrust.converter;

import com.zerotrust.zerotrust.entity.UserEntity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class UserConverterTest {
    private final UserConverter converter = new UserConverter();

    @ParameterizedTest
    @EnumSource(UserEntity.Status.class)
    void mapsAllResponseFieldsAndUsesPortalIdentifier(UserEntity.Status status) {
        UUID portalId = UUID.fromString("11111111-1111-1111-1111-111111111111");
        UserEntity user = spy(new UserEntity());
        user.setId(portalId);
        user.setKeycloakUserId(UUID.fromString("22222222-2222-2222-2222-222222222222"));
        user.setEmail("student@example.test");
        user.setUsername("student01");
        user.setFirstName("An");
        user.setLastName("Nguyen");
        user.setStatus(status);

        var response = converter.convertToDto(user);

        assertThat(response.getId()).isEqualTo(portalId.toString());
        assertThat(response.getEmail()).isEqualTo("student@example.test");
        assertThat(response.getUsername()).isEqualTo("student01");
        assertThat(response.getFirstName()).isEqualTo("An");
        assertThat(response.getLastName()).isEqualTo("Nguyen");
        assertThat(response.getStatus()).isEqualTo(status);
        verify(user, never()).getStudentEntity();
    }

    @Test
    void preservesNullFieldsWithoutStringifyingNullIdentifier() {
        UserEntity user = new UserEntity();
        user.setStatus(null);

        var response = converter.convertToDto(user);

        assertThat(response.getId()).isNull();
        assertThat(response.getEmail()).isNull();
        assertThat(response.getUsername()).isNull();
        assertThat(response.getFirstName()).isNull();
        assertThat(response.getLastName()).isNull();
        assertThat(response.getStatus()).isNull();
    }
}
