package com.zerotrust.zerotrust.repository;

import com.zerotrust.zerotrust.entity.SubjectEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.UUID;

public interface SubjectRepository extends JpaRepository<SubjectEntity, UUID> {
    boolean existsBySubjectCodeIgnoreCase(String subjectCode);

    @Query("""
            SELECT subject
            FROM SubjectEntity subject
            WHERE (
                :keyword IS NULL
                OR LOWER(subject.subjectCode) LIKE LOWER(CONCAT('%', :keyword, '%'))
                OR LOWER(subject.subjectName) LIKE LOWER(CONCAT('%', :keyword, '%'))
            )
            """)
    Page<SubjectEntity> findAllFiltered(
            @Param("keyword") String keyword,
            Pageable pageable);
}
