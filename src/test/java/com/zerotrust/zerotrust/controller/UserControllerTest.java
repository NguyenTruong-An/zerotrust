package com.zerotrust.zerotrust.controller;

import com.zerotrust.zerotrust.exception.ErrorCode;
import com.zerotrust.zerotrust.exception.WebException;
import com.zerotrust.zerotrust.model.response.ApiResponse;
import com.zerotrust.zerotrust.model.response.UserResponseDTO;
import com.zerotrust.zerotrust.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserControllerTest {

    @Mock
    private UserService userService;

    private UserController userController;

    @BeforeEach
    void setUp() {
        userController = new UserController(userService);
    }

    @Test
    void returnsCurrentUserIdentifiedByOidcSubject() {
        UUID keycloakUserId = UUID.randomUUID();
        OidcUser oidcUser = oidcUserWithSubject(keycloakUserId.toString());
        UserResponseDTO user = new UserResponseDTO();
        when(userService.getCurrentUser(keycloakUserId)).thenReturn(user);

        var response = userController.getCurrentUser(oidcUser);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isInstanceOf(ApiResponse.class);
        ApiResponse<?> body = (ApiResponse<?>) response.getBody();
        assertThat(body.getData()).isSameAs(user);
        assertThat(body.isSuccess()).isTrue();
        verify(userService).getCurrentUser(keycloakUserId);
    }

    @Test
    void rejectsOidcUserWithNonUuidSubject() {
        OidcUser oidcUser = oidcUserWithSubject("not-a-keycloak-uuid");

        assertThatThrownBy(() -> userController.getCurrentUser(oidcUser))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.UNAUTHORIZED);
    }

    private OidcUser oidcUserWithSubject(String subject) {
        OidcUser oidcUser = org.mockito.Mockito.mock(OidcUser.class);
        when(oidcUser.getSubject()).thenReturn(subject);
        return oidcUser;
    }
}
