-- Additive legacy migration. Never use schema.sql or synthetic seeds on a restored database.
-- MySQL DDL commits independently: partial failure requires restoring the approved copy.
CREATE TABLE teachers (
 id BINARY(16) NOT NULL, user_id BINARY(16) NOT NULL, teacher_code VARCHAR(30) NOT NULL,
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
 CONSTRAINT pk_teachers PRIMARY KEY (id),
 CONSTRAINT uk_teachers_user UNIQUE (user_id), CONSTRAINT uk_teachers_code UNIQUE (teacher_code),
 CONSTRAINT fk_teachers_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE teaching_assignments (
 id BINARY(16) NOT NULL, teacher_id BINARY(16) NOT NULL, class_id BINARY(16) NOT NULL, subject_id BINARY(16) NOT NULL,
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
 CONSTRAINT pk_teaching_assignments PRIMARY KEY (id),
 CONSTRAINT uk_assignment_teacher_class_subject UNIQUE (teacher_id,class_id,subject_id),
 CONSTRAINT fk_assignments_teacher FOREIGN KEY (teacher_id) REFERENCES teachers(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 CONSTRAINT fk_assignments_class FOREIGN KEY (class_id) REFERENCES student_classes(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 CONSTRAINT fk_assignments_subject FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE schedule_entries (
 id BINARY(16) NOT NULL, assignment_id BINARY(16) NOT NULL, weekday INTEGER NOT NULL,
 start_time TIME(6) NOT NULL, end_time TIME(6) NOT NULL, room VARCHAR(80) NOT NULL,
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
 CONSTRAINT pk_schedule_entries PRIMARY KEY (id),
 CONSTRAINT fk_schedule_assignment FOREIGN KEY (assignment_id) REFERENCES teaching_assignments(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 CONSTRAINT ck_schedule_time CHECK (weekday BETWEEN 1 AND 7 AND start_time < end_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE school_schema_history (
 version VARCHAR(64) NOT NULL PRIMARY KEY, checksum CHAR(64) NOT NULL,
 applied_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
