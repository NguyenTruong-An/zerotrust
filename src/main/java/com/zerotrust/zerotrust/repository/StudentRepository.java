package com.zerotrust.zerotrust.repository;

import com.zerotrust.zerotrust.entity.StudentEntity;
import com.zerotrust.zerotrust.entity.UserEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface StudentRepository extends JpaRepository<StudentEntity, UUID> {
    boolean existsByStudentCodeIgnoreCase(String studentCode);

    boolean existsByStudentCodeIgnoreCaseAndIdNot(String studentCode, UUID id);

    @EntityGraph(attributePaths = {"userEntity", "studentClassEntity"})
    @Query("""
            SELECT student
            FROM StudentEntity student
            JOIN student.userEntity userAccount
            JOIN student.studentClassEntity studentClass
            WHERE (
                :keyword IS NULL
                OR LOWER(student.studentCode) LIKE LOWER(CONCAT('%', :keyword, '%'))
                OR LOWER(userAccount.username) LIKE LOWER(CONCAT('%', :keyword, '%'))
                OR LOWER(userAccount.email) LIKE LOWER(CONCAT('%', :keyword, '%'))
                OR LOWER(userAccount.firstName) LIKE LOWER(CONCAT('%', :keyword, '%'))
                OR LOWER(userAccount.lastName) LIKE LOWER(CONCAT('%', :keyword, '%'))
            )
            AND (
                :classCode IS NULL
                OR LOWER(studentClass.classCode) = LOWER(:classCode)
            )
            AND (
                :status IS NULL
                OR userAccount.status = :status
            )
            """)
    Page<StudentEntity> findAllFiltered(
            @Param("keyword") String keyword,
            @Param("classCode") String classCode,
            @Param("status") UserEntity.Status status,
            Pageable pageable);

    @EntityGraph(attributePaths = {"userEntity", "studentClassEntity"})
    @Query("SELECT student FROM StudentEntity student WHERE student.id = :id")
    Optional<StudentEntity> findDetailedById(@Param("id") UUID id);
}
