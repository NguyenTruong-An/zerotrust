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
import org.springframework.security.oauth2.jwt.Jwt;

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
    void returnsCurrentUserIdentifiedByJwtSubject() {
        UUID keycloakUserId = UUID.randomUUID();
        Jwt jwt = jwtWithSubject(keycloakUserId.toString());
        UserResponseDTO user = new UserResponseDTO();
        when(userService.getCurrentUser(keycloakUserId)).thenReturn(user);

        var response = userController.getCurrentUser(jwt);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isInstanceOf(ApiResponse.class);
        ApiResponse<?> body = (ApiResponse<?>) response.getBody();
        assertThat(body.getData()).isSameAs(user);
        assertThat(body.isSuccess()).isTrue();
        verify(userService).getCurrentUser(keycloakUserId);
    }

    @Test
    void rejectsJwtWithNonUuidSubject() {
        Jwt jwt = jwtWithSubject("not-a-keycloak-uuid");

        assertThatThrownBy(() -> userController.getCurrentUser(jwt))
                .isInstanceOf(WebException.class)
                .extracting(exception -> ((WebException) exception).getErrorCode())
                .isEqualTo(ErrorCode.UNAUTHORIZED);
    }

    private Jwt jwtWithSubject(String subject) {
        Jwt jwt = org.mockito.Mockito.mock(Jwt.class);
        when(jwt.getSubject()).thenReturn(subject);
        return jwt;
    }
}
