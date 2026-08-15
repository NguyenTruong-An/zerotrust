package com.zerotrust.zerotrust.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "student_classes")
@Getter
@Setter
public class StudentClassEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "class_code", nullable = false, unique = true)
    private String classCode;

    @Column(name = "class_name", nullable = false, unique = true)
    private String className;

    @OneToMany(mappedBy = "studentClassEntity", cascade = CascadeType.ALL)
    private List<StudentEntity> studentEntities = new ArrayList<>();

    @Column(name = "department", nullable = false)
    private String department;

    @Column(name = "academic_year", nullable = false)
    private Integer academicYear;

    @Column(name = "create_at", nullable = false)
    private LocalDateTime createAt = LocalDateTime.now();

    @Column(name = "update_at",  nullable = false)
    private LocalDateTime updateAt = LocalDateTime.now();
}
