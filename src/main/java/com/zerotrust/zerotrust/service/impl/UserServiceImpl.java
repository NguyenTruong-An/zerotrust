package com.zerotrust.zerotrust.service.impl;

import com.zerotrust.zerotrust.converter.UserConverter;
import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.exception.ErrorNormalizer;
import com.zerotrust.zerotrust.model.identity.Credential;
import com.zerotrust.zerotrust.model.identity.TokenExchangeParam;
import com.zerotrust.zerotrust.model.identity.UserCreationParam;
import com.zerotrust.zerotrust.model.request.RegisterRequestDTO;
import com.zerotrust.zerotrust.model.response.UserResponseDTO;
import com.zerotrust.zerotrust.repository.IdentityClient;
import com.zerotrust.zerotrust.repository.UserRepository;
import com.zerotrust.zerotrust.service.UserService;
import feign.FeignException;
import lombok.RequiredArgsConstructor;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final IdentityClient identityClient;
    private final UserConverter userConverter;
    private final ErrorNormalizer errorNormalizer;

    @Value("${identity.client.client-id}")
    @NonFinal
    private String clientId;

    @Value("${identity.client.client-secret}")
    @NonFinal
    private String clientSecret;

    @Override
    public UserResponseDTO register(RegisterRequestDTO registerRequestDTO) {
        try {
            //Exchange Client Token
            var token = identityClient.exchangeToken(TokenExchangeParam.builder()
                    .grant_type("client_credentials")
                    .client_id(clientId)
                    .client_secret(clientSecret)
                    .scope("openid")
                    .build());
            log.info("Exchanged token: {}", token);

            //Get userId from Keycloak
            var creationResponse = identityClient.createUser(
                    "Bearer " + token.getAccessToken(),
                    UserCreationParam.builder()
                            .username(registerRequestDTO.getUsername())
                            .email(registerRequestDTO.getEmail())
                            .firstName(registerRequestDTO.getFirstName())
                            .lastName(registerRequestDTO.getLastName())
                            .enabled(true)
                            .emailVerified(false)
                            .credentials(List.of(Credential.builder()
                                    .type("password")
                                    .value(registerRequestDTO.getPassword())
                                    .temporary(false)
                                    .build()))
                            .build());

            UUID userId = extractUserId(creationResponse);
            log.info("Exchanged userId: {}", userId);
            log.info("User created in Keycloak: {}", creationResponse);

        UserEntity userEntity = userConverter.convertToEntity(registerRequestDTO);
        userEntity.setKeycloakUserId(userId);
        userRepository.save(userEntity);
            return null;

        } catch(FeignException ex) {
            throw errorNormalizer.handlerKeyCloakException(ex);
        }
    }

    @Override
    @PreAuthorize("hasAuthority('ADMIN')")
    public List<UserResponseDTO> getAllUsers() {
        var userEntities = userRepository.findAll();
        return userEntities.stream().map(userConverter::convertToDto).toList();
    }

    @Nullable
    private UUID extractUserId(ResponseEntity<?> response){
        String locationHeader = response.getHeaders().getFirst("Location");
        if (locationHeader != null && !locationHeader.isEmpty()) {
            String[] parts = locationHeader.split("/");
            return UUID.fromString(parts[parts.length - 1]);
        }
        return null;
    }
}
