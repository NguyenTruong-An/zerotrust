package com.zerotrust.zerotrust.entity;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "users")
@Getter
@Setter
public class UserEntity extends AuditableEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "keycloak_user_id", nullable = false, unique = true)
    private UUID keycloakUserId;

    @Column(name = "username", nullable = false, unique = true, length = 100)
    private String username;

    @Column(name = "first_name", nullable = false, length = 100)
    private String firstName;

    @Column(name = "last_name", nullable = false, length = 100)
    private String lastName;

    @Column(name = "email", nullable = false, unique = true, length = 254)
    private String email;

    @OneToOne(mappedBy = "userEntity", fetch = FetchType.LAZY)
    @JsonManagedReference("user-student")
    private StudentEntity studentEntity;

    @OneToOne(mappedBy = "userEntity", fetch = FetchType.LAZY)
    @JsonManagedReference("user-teacher")
    private TeacherEntity teacherEntity;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private Status status = Status.ACTIVE;

    public enum Status {
        ACTIVE, INACTIVE, DELETED
    }

    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;

    @PrePersist
    @PreUpdate
    void synchronizeDeletedAt() {
        deletedAt = status == Status.DELETED
                ? deletedAt == null ? LocalDateTime.now() : deletedAt
                : null;
    }
}
