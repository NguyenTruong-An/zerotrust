package com.zerotrust.zerotrust.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Table(name = "teachers")
@Entity
@Getter
@Setter
public class TeacherEntity extends AuditableEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    @JsonBackReference("user-teacher")
    private UserEntity userEntity;

    @Column(name = "teacher_code", nullable = false, unique = true, length = 30)
    private String teacherCode;

    @Column(name = "phone", length = 20)
    private String phone;

    @Column(name = "department", nullable = false, length = 150)
    private String department;

    @OneToMany(mappedBy = "teacherEntity")
    private List<SubjectClassEntity> subjectClassEntities = new ArrayList<>();
}
