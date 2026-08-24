package com.zerotrust.zerotrust.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum ErrorCode {
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "User not found"),
    USER_INACTIVE(HttpStatus.FORBIDDEN, "User account is inactive"),
    STUDENT_NOT_FOUND(HttpStatus.NOT_FOUND, "Student not found"),
    SUBJECT_NOT_FOUND(HttpStatus.NOT_FOUND, "Subject not found"),
    STUDENT_CLASS_NOT_FOUND(HttpStatus.NOT_FOUND, "Student class not found"),
    STUDENT_CLASS_CODE_EXISTS(HttpStatus.BAD_REQUEST, "Student class code already exists"),
    STUDENT_CODE_EXISTS(HttpStatus.BAD_REQUEST, "Student code already exists"),
    SUBJECT_CODE_EXISTS(HttpStatus.BAD_REQUEST, "Subject code already exists"),
    SCORE_NOT_FOUND(HttpStatus.NOT_FOUND, "Score not found"),
    SCORE_EXISTS(HttpStatus.BAD_REQUEST, "Score already exists for this student, subject and term"),
    INVALID_CREDENTIALS(HttpStatus.FORBIDDEN, "Invalid credentials"),
    EMAIL_EXISTS(HttpStatus.BAD_REQUEST, "Email already exists"),
    USERNAME_EXISTS(HttpStatus.BAD_REQUEST, "Username already exists"),
    USERNAME_IS_MISSING(HttpStatus.BAD_REQUEST, "Username is missing"),
    INVALID_REQUEST(HttpStatus.BAD_REQUEST, "Request validation failed"),
    IDENTITY_RESPONSE_INVALID(HttpStatus.BAD_GATEWAY, "Identity provider returned an invalid response"),
    IDENTITY_PROVIDER_FORBIDDEN(HttpStatus.BAD_GATEWAY, "Identity provider rejected the service account"),
    IDENTITY_ROLE_NOT_FOUND(HttpStatus.BAD_GATEWAY, "Required identity role is not configured"),
    IDENTITY_PROVIDER_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE, "Identity provider is unavailable"),
    UNCATEGORIZED_EXCEPTION(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred"),
    UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "Unauthorized access");

    private final HttpStatus status;
    private final String message;
}
