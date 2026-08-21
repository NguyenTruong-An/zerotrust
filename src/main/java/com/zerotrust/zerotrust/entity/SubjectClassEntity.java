package com.zerotrust.zerotrust.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.Check;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Entity
@Table(
        name = "subject_classes",
        indexes = {
                @Index(
                        name = "idx_subject_classes_subject_term",
                        columnList = "subject_id, academic_year, semester"),
                @Index(
                        name = "idx_subject_classes_teacher_term",
                        columnList = "teacher_id, academic_year, semester")
        })
@Getter
@Setter
@Check(constraints = "semester BETWEEN 1 AND 3")
public class SubjectClassEntity extends AuditableEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "subject_class_code", nullable = false, unique = true, length = 50)
    private String subjectClassCode;

    @OneToMany(mappedBy = "subjectClassEntity")
    private List<ScoreEntity> scoreEntities = new ArrayList<>();

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "teacher_id", nullable = false)
    private TeacherEntity teacherEntity;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "subject_id", nullable = false)
    private SubjectEntity subjectEntity;

    @Column(name = "semester", nullable = false, columnDefinition = "TINYINT UNSIGNED")
    private Short semester;

    @Column(name = "academic_year", nullable = false, length = 9)
    private String academicYear;
}
