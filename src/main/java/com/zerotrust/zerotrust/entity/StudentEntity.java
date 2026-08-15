package com.zerotrust.zerotrust.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "students")
@Getter
@Setter
public class StudentEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @OneToOne
    @JoinColumn(name = "user_id", unique = true)
    @JsonBackReference
    private UserEntity userEntity;

    @Column(name = "student_code", nullable = false, unique = true)
    private String studentCode;

    @Column(name = "full_name", nullable = false)
    private String fullName;

    @Column(name = "date_of_birth", nullable = false)
    private LocalDate dateOfBirth;

    @Column(name = "gender", nullable = false)
    private String gender;

    @Column(name = "phone", nullable = false)
    private String phone;

    @Column(name = "address", nullable = false)
    private String address;

    @ManyToOne
    @JoinColumn(name = "class_id")
    private StudentClassEntity studentClassEntity;

    @OneToMany(mappedBy = "studentEntity")
    private List<ScoreEntity> scoreEntities;

    @Column(name = "create_at", nullable = false)
    private LocalDate createAt = LocalDate.now();

    @Column(name = "update_at", nullable = false)
    private LocalDate updateAt = LocalDate.now();
}
