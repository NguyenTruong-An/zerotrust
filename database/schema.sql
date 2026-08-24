-- Portal Resource Server database schema
-- Target: MySQL 8.0+
-- Roles are managed by Keycloak. Users are soft-deleted with status = 'DELETED'.

CREATE DATABASE IF NOT EXISTS `vip_pro`
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE `vip_pro`;

-- =========================================================
-- Identity and local profiles
-- =========================================================

CREATE TABLE `users` (
    `id` BINARY(16) NOT NULL,
    `keycloak_user_id` BINARY(16) NOT NULL,
    `username` VARCHAR(100) NOT NULL,
    `email` VARCHAR(254) NOT NULL,
    `first_name` VARCHAR(100) NOT NULL,
    `last_name` VARCHAR(100) NOT NULL,
    `status` ENUM('ACTIVE', 'INACTIVE', 'DELETED') NOT NULL DEFAULT 'ACTIVE',
    `created_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    `deleted_at` DATETIME(6) NULL,

    CONSTRAINT `pk_users` PRIMARY KEY (`id`),
    CONSTRAINT `uk_users_keycloak_user_id` UNIQUE (`keycloak_user_id`),
    CONSTRAINT `uk_users_username` UNIQUE (`username`),
    CONSTRAINT `uk_users_email` UNIQUE (`email`),
    CONSTRAINT `ck_users_deleted_at` CHECK (
        (`status` = 'DELETED' AND `deleted_at` IS NOT NULL)
        OR (`status` <> 'DELETED' AND `deleted_at` IS NULL)
    )
) ENGINE = InnoDB;

CREATE TABLE `student_classes` (
    `id` BINARY(16) NOT NULL,
    `class_code` VARCHAR(30) NOT NULL,
    `class_name` VARCHAR(100) NOT NULL,
    `department` VARCHAR(150) NOT NULL,
    `academic_year` VARCHAR(9) NOT NULL COMMENT 'Example: 2025-2026',
    `created_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),

    CONSTRAINT `pk_student_classes` PRIMARY KEY (`id`),
    CONSTRAINT `uk_student_classes_code` UNIQUE (`class_code`)
) ENGINE = InnoDB;

CREATE TABLE `students` (
    `id` BINARY(16) NOT NULL,
    `user_id` BINARY(16) NOT NULL,
    `class_id` BINARY(16) NOT NULL,
    `student_code` VARCHAR(30) NOT NULL,
    `date_of_birth` DATE NOT NULL,
    `gender` VARCHAR(20) NOT NULL,
    `phone` VARCHAR(20) NULL,
    `address` VARCHAR(500) NULL,
    `created_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),

    CONSTRAINT `pk_students` PRIMARY KEY (`id`),
    CONSTRAINT `uk_students_user_id` UNIQUE (`user_id`),
    CONSTRAINT `uk_students_student_code` UNIQUE (`student_code`),
    CONSTRAINT `fk_students_user`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT `fk_students_class`
        FOREIGN KEY (`class_id`) REFERENCES `student_classes` (`id`)
        ON UPDATE RESTRICT ON DELETE RESTRICT,

    INDEX `idx_students_class_id` (`class_id`)
) ENGINE = InnoDB;

-- =========================================================
-- Academic data
-- =========================================================

CREATE TABLE `subjects` (
    `id` BINARY(16) NOT NULL,
    `subject_code` VARCHAR(30) NOT NULL,
    `subject_name` VARCHAR(200) NOT NULL,
    `credits` TINYINT UNSIGNED NOT NULL,
    `description` TEXT NULL,
    `created_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),

    CONSTRAINT `pk_subjects` PRIMARY KEY (`id`),
    CONSTRAINT `uk_subjects_code` UNIQUE (`subject_code`),
    CONSTRAINT `ck_subjects_credits` CHECK (`credits` BETWEEN 1 AND 20)
) ENGINE = InnoDB;

-- Each score belongs directly to a student and subject in a specific term.
-- Score fields remain NULL until an administrator enters them.
CREATE TABLE `scores` (
    `id` BINARY(16) NOT NULL,
    `student_id` BINARY(16) NOT NULL,
    `subject_id` BINARY(16) NOT NULL,
    `semester` TINYINT UNSIGNED NOT NULL,
    `academic_year` VARCHAR(9) NOT NULL COMMENT 'Example: 2025-2026',
    `attendance_score` DECIMAL(4,2) NULL,
    `midterm_score` DECIMAL(4,2) NULL,
    `final_score` DECIMAL(4,2) NULL,
    `total_score` DECIMAL(4,2) NULL,
    `grade` VARCHAR(5) NULL,
    `created_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),

    CONSTRAINT `pk_scores` PRIMARY KEY (`id`),
    CONSTRAINT `uk_scores_student_subject_term`
        UNIQUE (`student_id`, `subject_id`, `semester`, `academic_year`),
    CONSTRAINT `ck_scores_semester` CHECK (`semester` BETWEEN 1 AND 3),
    CONSTRAINT `ck_scores_attendance` CHECK (
        `attendance_score` IS NULL OR `attendance_score` BETWEEN 0 AND 10
    ),
    CONSTRAINT `ck_scores_midterm` CHECK (
        `midterm_score` IS NULL OR `midterm_score` BETWEEN 0 AND 10
    ),
    CONSTRAINT `ck_scores_final` CHECK (
        `final_score` IS NULL OR `final_score` BETWEEN 0 AND 10
    ),
    CONSTRAINT `ck_scores_total` CHECK (
        `total_score` IS NULL OR `total_score` BETWEEN 0 AND 10
    ),
    CONSTRAINT `fk_scores_student`
        FOREIGN KEY (`student_id`) REFERENCES `students` (`id`)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT `fk_scores_subject`
        FOREIGN KEY (`subject_id`) REFERENCES `subjects` (`id`)
        ON UPDATE RESTRICT ON DELETE RESTRICT,

    INDEX `idx_scores_subject_term` (`subject_id`, `academic_year`, `semester`)
) ENGINE = InnoDB;
