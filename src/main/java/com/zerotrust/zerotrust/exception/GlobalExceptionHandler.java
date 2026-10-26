package com.zerotrust.zerotrust.exception;

import com.zerotrust.zerotrust.model.response.ApiErrorResponse;
import jakarta.persistence.OptimisticLockException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler({OptimisticLockingFailureException.class, OptimisticLockException.class})
    public ResponseEntity<ApiErrorResponse> handleOptimisticLocking(HttpServletRequest request) {
        ErrorCode errorCode = ErrorCode.CONCURRENT_MODIFICATION;
        return errorResponse(errorCode, errorCode.getMessage(), request);
    }

    @ExceptionHandler(WebException.class)
    public ResponseEntity<ApiErrorResponse> handleBusiness(
            WebException ex,
            HttpServletRequest request
    ) {
        ErrorCode errorCode = ex.getErrorCode();

        Object message = ex.getDetails() != null ? ex.getDetails() : errorCode.getMessage();
        return errorResponse(errorCode, message, request);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiErrorResponse> handleValidation(
            MethodArgumentNotValidException ex,
            HttpServletRequest request
    ) {
        Map<String, String> errors = new LinkedHashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error ->
                errors.putIfAbsent(error.getField(), error.getDefaultMessage()));

        return errorResponse(ErrorCode.INVALID_REQUEST, errors, request);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiErrorResponse> handleUnreadableBody(
            HttpMessageNotReadableException ex,
            HttpServletRequest request) {
        return errorResponse(ErrorCode.INVALID_REQUEST, "Request body is missing or malformed", request);
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ApiErrorResponse> handleTypeMismatch(
            MethodArgumentTypeMismatchException ex,
            HttpServletRequest request) {
        return errorResponse(
                ErrorCode.INVALID_REQUEST, "Parameter '" + ex.getName() + "' has an invalid value", request);
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ApiErrorResponse> handleMissingParameter(
            MissingServletRequestParameterException ex,
            HttpServletRequest request) {
        return errorResponse(
                ErrorCode.INVALID_REQUEST, "Parameter '" + ex.getParameterName() + "' is required", request);
    }

    private ResponseEntity<ApiErrorResponse> errorResponse(
            ErrorCode errorCode,
            Object message,
            HttpServletRequest request) {
        ApiErrorResponse response = ApiErrorResponse.builder()
                .status(errorCode.getStatus().value())
                .error(errorCode.name())
                .message(message)
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(errorCode.getStatus()).body(response);
    }
}
