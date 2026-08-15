package com.zerotrust.zerotrust.repository;

import com.zerotrust.zerotrust.model.identity.TokenExchangeParam;
import com.zerotrust.zerotrust.model.identity.TokenExchangeResponse;
import com.zerotrust.zerotrust.model.identity.UserCreationParam;
import feign.QueryMap;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

@FeignClient(name= "identity-client", url = "${identity.client.url}")
public interface IdentityClient {
    @PostMapping(value = "/realms/DoAn/protocol/openid-connect/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    TokenExchangeResponse exchangeToken(@QueryMap TokenExchangeParam tokenExchangeParam);

    @PostMapping(value = "/admin/realms/DoAn/users", consumes = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<?> createUser(
            @RequestHeader("Authorization") String authorization,
            @RequestBody UserCreationParam userCreationParam);
}
