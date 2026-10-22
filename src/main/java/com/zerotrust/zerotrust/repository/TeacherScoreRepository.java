package com.zerotrust.zerotrust.repository;

import com.zerotrust.zerotrust.entity.ScoreEntity;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import java.util.*;

public interface TeacherScoreRepository extends JpaRepository<ScoreEntity, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select s from ScoreEntity s where s.studentEntity.id = :student and s.subjectEntity.id = :subject")
    Optional<ScoreEntity> lockByStudentAndSubject(@Param("student") UUID student, @Param("subject") UUID subject);
    Optional<ScoreEntity> findByStudentEntityIdAndSubjectEntityId(UUID student, UUID subject);
}
