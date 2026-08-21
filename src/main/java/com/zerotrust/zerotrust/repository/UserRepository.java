package com.zerotrust.zerotrust.repository;

import com.zerotrust.zerotrust.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<UserEntity, UUID> {
    boolean existsByUsernameIgnoreCase(String username);

    boolean existsByEmailIgnoreCase(String email);

    Optional<UserEntity> findByKeycloakUserId(UUID keycloakUserId);
}
