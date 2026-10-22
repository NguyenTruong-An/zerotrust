package com.zerotrust.zerotrust.repository;

import com.zerotrust.zerotrust.entity.TeachingAssignmentEntity;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import org.springframework.data.domain.Pageable;
import java.util.*;

public interface TeachingAssignmentRepository extends JpaRepository<TeachingAssignmentEntity, UUID> {
    @EntityGraph(attributePaths = {"teacherEntity.userEntity", "studentClassEntity", "subjectEntity"})
    List<TeachingAssignmentEntity> findByTeacherEntityIdOrderById(UUID id, Pageable pageable);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select a from TeachingAssignmentEntity a where a.id = :id")
    Optional<TeachingAssignmentEntity> lockById(@Param("id") UUID id);
}
