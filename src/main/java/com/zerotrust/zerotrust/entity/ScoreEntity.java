package com.zerotrust.zerotrust.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.Check;

import java.math.BigDecimal;
import java.util.UUID;

@Entity
@Table(
        name = "scores",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_scores_student_subject_term",
                        columnNames = {"student_id", "subject_id", "semester", "academic_year"})
        },
        indexes = {
                @Index(
                        name = "idx_scores_subject_term",
                        columnList = "subject_id, academic_year, semester")
        })
@Getter
@Setter
@Check(constraints = "semester BETWEEN 1 AND 3")
@Check(constraints = "attendance_score IS NULL OR attendance_score BETWEEN 0 AND 10")
@Check(constraints = "midterm_score IS NULL OR midterm_score BETWEEN 0 AND 10")
@Check(constraints = "final_score IS NULL OR final_score BETWEEN 0 AND 10")
@Check(constraints = "total_score IS NULL OR total_score BETWEEN 0 AND 10")
public class ScoreEntity extends AuditableEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "attendance_score", precision = 4, scale = 2)
    private BigDecimal attendanceScore;

    @Column(name = "midterm_score", precision = 4, scale = 2)
    private BigDecimal midtermScore;

    @Column(name = "final_score", precision = 4, scale = 2)
    private BigDecimal finalScore;

    @Column(name = "total_score", precision = 4, scale = 2)
    private BigDecimal totalScore;

    @Column(name = "grade", length = 5)
    private String grade;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "student_id", nullable = false)
    private StudentEntity studentEntity;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "subject_id", nullable = false)
    private SubjectEntity subjectEntity;

    @Column(name = "semester", nullable = false, columnDefinition = "TINYINT UNSIGNED")
    private Short semester;

    @Column(name = "academic_year", nullable = false, length = 9)
    private String academicYear;
}
