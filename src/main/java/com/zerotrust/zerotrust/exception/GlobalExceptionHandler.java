package com.zerotrust.zerotrust.exception;

import com.zerotrust.zerotrust.model.response.ApiErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

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
}
