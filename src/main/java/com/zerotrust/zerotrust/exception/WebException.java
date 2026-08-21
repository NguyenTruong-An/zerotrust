package com.zerotrust.zerotrust.exception;

import lombok.Getter;

@Getter
public class WebException extends RuntimeException {

    private final ErrorCode errorCode;
    private final Object details;

    public WebException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
        this.details = null;
    }

    public WebException(ErrorCode errorCode, Object details) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
        this.details = details;
    }
}
