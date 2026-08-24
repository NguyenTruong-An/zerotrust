package com.zerotrust.zerotrust.repository;

import com.zerotrust.zerotrust.entity.ScoreEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface ScoreRepository extends JpaRepository<ScoreEntity, UUID> {
    boolean existsByStudentEntityIdAndSubjectEntityIdAndSemesterAndAcademicYear(
            UUID studentId,
            UUID subjectId,
            Short semester,
            String academicYear);

    boolean existsByStudentEntityIdAndSubjectEntityIdAndSemesterAndAcademicYearAndIdNot(
            UUID studentId,
            UUID subjectId,
            Short semester,
            String academicYear,
            UUID excludedScoreId);
}
