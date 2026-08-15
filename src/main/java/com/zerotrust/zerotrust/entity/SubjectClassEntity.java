package com.zerotrust.zerotrust.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "subject_classes",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = { "subject_id", "semester", "academic_year"})
        })
@Getter
@Setter
public class SubjectClassEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @OneToMany(mappedBy = "subjectClassEntity")
    private List<ScoreEntity> scoreEntities;

    @ManyToOne
    @JoinColumn(name = "teacher_id")
    private TeacherEntity teacherEntity;

    @ManyToOne
    @JoinColumn(name = "subject_id")
    private SubjectEntity subjectEntity;

    @OneToMany(mappedBy = "subjectClassEntity")
    private List<ScheduleEntity> scheduleEntities = new ArrayList<>();

    @Column(name = "semester",  nullable = false)
    private String semester;

    @Column(name = "academic_year",  nullable = false)
    private String academicYear;

    @Column(name = "create_at", nullable = false)
    private LocalDateTime createAt = LocalDateTime.now();
}
