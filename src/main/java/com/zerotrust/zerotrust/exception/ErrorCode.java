package com.zerotrust.zerotrust.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum ErrorCode {
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "User not found"),
    INVALID_CREDENTIALS(HttpStatus.FORBIDDEN, "Invalid credentials"),
    EMAIL_EXISTS(HttpStatus.BAD_REQUEST, "Email already exists"),
    USERNAME_EXISTS(HttpStatus.BAD_REQUEST, "Username already exists"),
    USERNAME_IS_MISSING(HttpStatus.BAD_REQUEST, "Username is missing"),
    UNCATEGORIZED_EXCEPTION(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred"),
    UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "Unauthorized access");

    private final HttpStatus status;
    private final String message;
}
