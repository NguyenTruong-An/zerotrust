package com.zerotrust.zerotrust.repository;

import com.zerotrust.zerotrust.entity.ScoreEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

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

    @EntityGraph(attributePaths = {"studentEntity", "subjectEntity"})
    @Query("""
            SELECT score
            FROM ScoreEntity score
            WHERE score.studentEntity.id = :studentId
            AND (
                :subjectId IS NULL
                OR score.subjectEntity.id = :subjectId
            )
            AND (
                :semester IS NULL
                OR score.semester = :semester
            )
            AND (
                :academicYear IS NULL
                OR score.academicYear = :academicYear
            )
            """)
    Page<ScoreEntity> findAllByStudentFiltered(
            @Param("studentId") UUID studentId,
            @Param("subjectId") UUID subjectId,
            @Param("semester") Short semester,
            @Param("academicYear") String academicYear,
            Pageable pageable);
}
