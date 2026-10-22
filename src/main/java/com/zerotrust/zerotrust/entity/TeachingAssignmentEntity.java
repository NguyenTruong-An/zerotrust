package com.zerotrust.zerotrust.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.util.UUID;

@Entity
@Table(name = "teaching_assignments", uniqueConstraints = @UniqueConstraint(
        name = "uk_assignment_teacher_class_subject", columnNames = {"teacher_id", "class_id", "subject_id"}))
@Getter @Setter
public class TeachingAssignmentEntity extends AuditableEntity {
    @Id @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "teacher_id", nullable = false, foreignKey = @ForeignKey(name = "fk_assignments_teacher"))
    private TeacherEntity teacherEntity;
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "class_id", nullable = false, foreignKey = @ForeignKey(name = "fk_assignments_class"))
    private StudentClassEntity studentClassEntity;
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "subject_id", nullable = false, foreignKey = @ForeignKey(name = "fk_assignments_subject"))
    private SubjectEntity subjectEntity;
}
