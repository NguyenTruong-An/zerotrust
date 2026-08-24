package com.zerotrust.zerotrust.repository;

import com.zerotrust.zerotrust.entity.StudentClassEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface StudentClassRepository extends JpaRepository<StudentClassEntity, UUID> {
    boolean existsByClassCodeIgnoreCase(String classCode);

    Optional<StudentClassEntity> findByClassCodeIgnoreCase(String classCode);

    @Query("""
            SELECT studentClass
            FROM StudentClassEntity studentClass
            WHERE (
                :keyword IS NULL
                OR LOWER(studentClass.classCode) LIKE LOWER(CONCAT('%', :keyword, '%'))
                OR LOWER(studentClass.className) LIKE LOWER(CONCAT('%', :keyword, '%'))
            )
            AND (
                :department IS NULL
                OR LOWER(studentClass.department) = LOWER(:department)
            )
            AND (
                :academicYear IS NULL
                OR studentClass.academicYear = :academicYear
            )
            """)
    Page<StudentClassEntity> findAllFiltered(
            @Param("keyword") String keyword,
            @Param("department") String department,
            @Param("academicYear") String academicYear,
            Pageable pageable);
}
