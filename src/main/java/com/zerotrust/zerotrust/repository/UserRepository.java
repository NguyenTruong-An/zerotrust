package com.zerotrust.zerotrust.repository;

import com.zerotrust.zerotrust.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface UserRepository extends JpaRepository<UserEntity, UUID> {
}
