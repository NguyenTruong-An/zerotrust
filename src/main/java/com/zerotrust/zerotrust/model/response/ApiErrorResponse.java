package com.zerotrust.zerotrust.model.response;

import com.zerotrust.zerotrust.exception.ErrorCode;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class ApiErrorResponse {
    private int status;
    private String error;
    private Object message;
    private String path;

    public static ApiErrorResponse of(ErrorCode errorCode, String path) {
        return new ApiErrorResponse(
                errorCode.getStatus().value(),
                errorCode.name(),
                errorCode.getMessage(),
                path
        );
    }

}
