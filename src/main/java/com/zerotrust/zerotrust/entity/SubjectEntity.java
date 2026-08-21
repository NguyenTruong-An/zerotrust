package com.zerotrust.zerotrust.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.Check;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "subjects")
@Getter
@Setter
@Check(constraints = "credits BETWEEN 1 AND 20")
public class SubjectEntity extends AuditableEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "subject_code", nullable = false, unique = true, length = 30)
    private String subjectCode;

    @Column(name = "subject_name", nullable = false, length = 200)
    private String subjectName;

    @Column(name = "credits", nullable = false, columnDefinition = "TINYINT UNSIGNED")
    private Short credits;

    @Lob
    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @OneToMany(mappedBy = "subjectEntity")
    private List<SubjectClassEntity> subjectClassEntities = new ArrayList<>();
}
