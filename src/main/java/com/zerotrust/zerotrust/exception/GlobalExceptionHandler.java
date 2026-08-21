package com.zerotrust.zerotrust.exception;

import com.zerotrust.zerotrust.model.response.ApiErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(WebException.class)
    public ResponseEntity<ApiErrorResponse> handleBusiness(
            WebException ex,
            HttpServletRequest request
    ) {
        ErrorCode errorCode = ex.getErrorCode();

        ApiErrorResponse response = ApiErrorResponse.builder()
                .status(errorCode.getStatus().value())
                .error(errorCode.name())
                .message(
                        ex.getDetails() != null
                                ? ex.getDetails()
                                : errorCode.getMessage()
                )
                .path(request.getRequestURI())
                .build();

        return ResponseEntity
                .status(errorCode.getStatus())
                .body(response);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiErrorResponse> handleValidation(
            MethodArgumentNotValidException ex,
            HttpServletRequest request
    ) {
        Map<String, String> errors = new LinkedHashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error ->
                errors.putIfAbsent(error.getField(), error.getDefaultMessage()));

        ErrorCode errorCode = ErrorCode.INVALID_REQUEST;
        ApiErrorResponse response = ApiErrorResponse.builder()
                .status(errorCode.getStatus().value())
                .error(errorCode.name())
                .message(errors)
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(errorCode.getStatus()).body(response);
    }
}
