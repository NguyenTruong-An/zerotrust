package com.zerotrust.zerotrust.repository;

import com.zerotrust.zerotrust.entity.TeacherEntity;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import java.util.Optional;
import java.util.UUID;

public interface TeacherRepository extends JpaRepository<TeacherEntity, UUID> {
    @EntityGraph(attributePaths = "userEntity")
    Optional<TeacherEntity> findByUserEntityKeycloakUserId(UUID subject);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select t from TeacherEntity t join fetch t.userEntity where t.userEntity.keycloakUserId = :subject")
    Optional<TeacherEntity> lockBySubject(@Param("subject") UUID subject);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select t from TeacherEntity t join fetch t.userEntity where t.id = :id")
    Optional<TeacherEntity> lockById(@Param("id") UUID id);
    boolean existsByTeacherCodeIgnoreCase(String code);
    boolean existsByTeacherCodeIgnoreCaseAndIdNot(String code, UUID id);
}
