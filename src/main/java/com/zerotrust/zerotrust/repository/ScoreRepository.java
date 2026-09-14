package com.zerotrust.zerotrust.repository;

import com.zerotrust.zerotrust.entity.ScoreEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.UUID;
import java.util.Collection;
import java.util.List;

public interface ScoreRepository extends JpaRepository<ScoreEntity, UUID> {
    boolean existsBySubjectEntityId(UUID subjectId);

    boolean existsByStudentEntityIdAndSubjectEntityId(UUID studentId, UUID subjectId);

    boolean existsByStudentEntityIdAndSubjectEntityIdAndIdNot(
            UUID studentId,
            UUID subjectId,
            UUID excludedScoreId);

    @EntityGraph(attributePaths = {"studentEntity", "subjectEntity"})
    List<ScoreEntity> findAllBySubjectEntityIdAndStudentEntityIdIn(
            UUID subjectId,
            Collection<UUID> studentIds);

    List<ScoreEntity> findAllByStudentEntityId(UUID studentId);

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
                :keyword IS NULL
                OR LOWER(score.subjectEntity.subjectCode)
                    LIKE LOWER(CONCAT('%', :keyword, '%'))
                OR LOWER(score.subjectEntity.subjectName)
                    LIKE LOWER(CONCAT('%', :keyword, '%'))
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
            @Param("keyword") String keyword,
            @Param("semester") Short semester,
            @Param("academicYear") String academicYear,
            Pageable pageable);
}
