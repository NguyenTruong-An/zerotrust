package com.zerotrust.zerotrust.exception;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.zerotrust.model.identity.KeyCloakError;
import feign.FeignException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Component
@Slf4j
public class ErrorNormalizer {
    private final ObjectMapper objectMapper;
    private final Map<String, ErrorCode> errorCodeMap;

    public ErrorNormalizer() {
        this.objectMapper = new ObjectMapper();
        this.errorCodeMap = new HashMap<>();

        errorCodeMap.put("Username already exists", ErrorCode.USERNAME_EXISTS);
        errorCodeMap.put("User exists with same email", ErrorCode.EMAIL_EXISTS);
        errorCodeMap.put("Username is missing", ErrorCode.USERNAME_IS_MISSING);
    }

    public WebException handlerKeyCloakException(FeignException feignException){
        try {
            log.warn("Cannot complete request", feignException);
            var response = objectMapper.readValue(feignException.contentUTF8(), KeyCloakError.class);
            if (Objects.nonNull(response.getErrorMessage()) && Objects.nonNull(errorCodeMap.get(response.getErrorMessage()))) {
                return new WebException(errorCodeMap.get(response.getErrorMessage()));
            }
        } catch (JsonProcessingException e) {
            log.error("Error occurred while processing KeyCloak error response", e);
        }
        return new WebException(ErrorCode.UNCATEGORIZED_EXCEPTION);
    }
}
