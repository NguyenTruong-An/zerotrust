package com.zerotrust.zerotrust.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.util.UUID;

@Entity
@Table(name = "teachers")
@Getter @Setter
public class TeacherEntity extends AuditableEntity {
    @Id @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, unique = true,
            foreignKey = @ForeignKey(name = "fk_teachers_user"))
    private UserEntity userEntity;
    @Column(name = "teacher_code", nullable = false, unique = true, length = 30)
    private String teacherCode;
}
