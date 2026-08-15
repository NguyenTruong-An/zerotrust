package com.zerotrust.zerotrust.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "scores",
        uniqueConstraints = {
        @UniqueConstraint(columnNames = {"student_id", "subject_class_id"})
        })
@Getter
@Setter
public class ScoreEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name= "attendance_score", nullable = false)
    private int attendanceScore;

    @Column(name= "midterm_score", nullable = false)
    private int midtermScore;

    @Column(name= "final_score", nullable = false)
    private int finalScore;

    @Column(name= "total_score", nullable = false)
    private int totalScore;

    @Column(name= "grade", nullable = false)
    private String grade;

    @ManyToOne
    @JoinColumn(name = "student_id")
    private StudentEntity studentEntity;

    @ManyToOne
    @JoinColumn(name = "subject_class_id")
    private SubjectClassEntity subjectClassEntity;

    @Column(name = "create_at", nullable = false)
    private LocalDateTime createAt = LocalDateTime.now();

    @Column(name = "update_at", nullable = false)
    private LocalDateTime updateAt = LocalDateTime.now();
}
