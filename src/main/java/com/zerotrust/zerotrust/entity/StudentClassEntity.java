package com.zerotrust.zerotrust.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "student_classes")
@Getter
@Setter
public class StudentClassEntity extends AuditableEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "class_code", nullable = false, unique = true, length = 30)
    private String classCode;

    @Column(name = "class_name", nullable = false, length = 100)
    private String className;

    @OneToMany(mappedBy = "studentClassEntity")
    private List<StudentEntity> studentEntities = new ArrayList<>();

    @Column(name = "department", nullable = false, length = 150)
    private String department;

    @Column(name = "academic_year", nullable = false, length = 9)
    private String academicYear;
}
