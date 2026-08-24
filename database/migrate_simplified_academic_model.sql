-- Migrates the original teacher/subject-class model to the simplified model.
-- Target: MySQL 8.0.16+
-- Back up the database before running this script.
-- The migration can be run again after a partial or completed migration.

USE `vip_pro`;

DROP PROCEDURE IF EXISTS `migrate_simplified_academic_model`;

DELIMITER $$

CREATE PROCEDURE `migrate_simplified_academic_model`()
migration: BEGIN
    DECLARE has_subject_class_id INT DEFAULT 0;
    DECLARE has_subject_id INT DEFAULT 0;
    DECLARE has_semester INT DEFAULT 0;
    DECLARE has_academic_year INT DEFAULT 0;
    DECLARE has_subject_classes_table INT DEFAULT 0;
    DECLARE old_subject_class_fk VARCHAR(64) DEFAULT NULL;

    SELECT COUNT(*) INTO has_subject_class_id
    FROM `information_schema`.`columns`
    WHERE `table_schema` = DATABASE()
      AND `table_name` = 'scores'
      AND `column_name` = 'subject_class_id';

    SELECT COUNT(*) INTO has_subject_id
    FROM `information_schema`.`columns`
    WHERE `table_schema` = DATABASE()
      AND `table_name` = 'scores'
      AND `column_name` = 'subject_id';

    SELECT COUNT(*) INTO has_semester
    FROM `information_schema`.`columns`
    WHERE `table_schema` = DATABASE()
      AND `table_name` = 'scores'
      AND `column_name` = 'semester';

    SELECT COUNT(*) INTO has_academic_year
    FROM `information_schema`.`columns`
    WHERE `table_schema` = DATABASE()
      AND `table_name` = 'scores'
      AND `column_name` = 'academic_year';

    IF has_subject_class_id = 0
            AND (has_subject_id = 0 OR has_semester = 0 OR has_academic_year = 0) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'scores is neither the supported legacy schema nor the new schema';
    END IF;

    IF has_subject_id = 0 THEN
        ALTER TABLE `scores`
            ADD COLUMN `subject_id` BINARY(16) NULL AFTER `student_id`;
    END IF;

    IF has_semester = 0 THEN
        ALTER TABLE `scores`
            ADD COLUMN `semester` TINYINT UNSIGNED NULL AFTER `subject_id`;
    END IF;

    IF has_academic_year = 0 THEN
        ALTER TABLE `scores`
            ADD COLUMN `academic_year` VARCHAR(9) NULL AFTER `semester`;
    END IF;

    IF has_subject_class_id = 1 THEN
        SELECT COUNT(*) INTO has_subject_classes_table
        FROM `information_schema`.`tables`
        WHERE `table_schema` = DATABASE()
          AND `table_name` = 'subject_classes';

        IF has_subject_classes_table = 0 THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'subject_classes is required to migrate legacy score rows';
        END IF;

        UPDATE `scores` AS `score`
        INNER JOIN `subject_classes` AS `subject_class`
            ON `subject_class`.`id` = `score`.`subject_class_id`
        SET
            `score`.`subject_id` = `subject_class`.`subject_id`,
            `score`.`semester` = `subject_class`.`semester`,
            `score`.`academic_year` = `subject_class`.`academic_year`;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM `scores`
        WHERE `subject_id` IS NULL
           OR `semester` IS NULL
           OR `academic_year` IS NULL
    ) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'some score rows could not be assigned a subject and term';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM `scores`
        GROUP BY `student_id`, `subject_id`, `semester`, `academic_year`
        HAVING COUNT(*) > 1
    ) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'duplicate scores exist for the same student, subject and term';
    END IF;

    -- Add the replacement unique index before removing the legacy one.
    -- Its student_id prefix keeps fk_scores_student backed by a valid index.
    IF NOT EXISTS (
        SELECT 1
        FROM `information_schema`.`statistics`
        WHERE `table_schema` = DATABASE()
          AND `table_name` = 'scores'
          AND `index_name` = 'uk_scores_student_subject_term'
    ) THEN
        ALTER TABLE `scores`
            ADD CONSTRAINT `uk_scores_student_subject_term`
                UNIQUE (`student_id`, `subject_id`, `semester`, `academic_year`);
    END IF;

    IF has_subject_class_id = 1 THEN
        SELECT MAX(`constraint_name`) INTO old_subject_class_fk
        FROM `information_schema`.`key_column_usage`
        WHERE `constraint_schema` = DATABASE()
          AND `table_name` = 'scores'
          AND `column_name` = 'subject_class_id'
          AND `referenced_table_name` IS NOT NULL;

        IF old_subject_class_fk IS NOT NULL THEN
            SET @drop_old_subject_class_fk = CONCAT(
                    'ALTER TABLE `scores` DROP FOREIGN KEY `',
                    REPLACE(old_subject_class_fk, '`', '``'),
                    '`');
            PREPARE drop_old_subject_class_fk
                FROM @drop_old_subject_class_fk;
            EXECUTE drop_old_subject_class_fk;
            DEALLOCATE PREPARE drop_old_subject_class_fk;
        END IF;

        IF EXISTS (
            SELECT 1
            FROM `information_schema`.`statistics`
            WHERE `table_schema` = DATABASE()
              AND `table_name` = 'scores'
              AND `index_name` = 'uk_scores_student_subject_class'
        ) THEN
            ALTER TABLE `scores`
                DROP INDEX `uk_scores_student_subject_class`;
        END IF;

        IF EXISTS (
            SELECT 1
            FROM `information_schema`.`statistics`
            WHERE `table_schema` = DATABASE()
              AND `table_name` = 'scores'
              AND `index_name` = 'idx_scores_subject_class_id'
        ) THEN
            ALTER TABLE `scores`
                DROP INDEX `idx_scores_subject_class_id`;
        END IF;

        ALTER TABLE `scores`
            DROP COLUMN `subject_class_id`;
    END IF;

    ALTER TABLE `scores`
        MODIFY COLUMN `subject_id` BINARY(16) NOT NULL,
        MODIFY COLUMN `semester` TINYINT UNSIGNED NOT NULL,
        MODIFY COLUMN `academic_year` VARCHAR(9) NOT NULL;

    IF NOT EXISTS (
        SELECT 1
        FROM `information_schema`.`table_constraints`
        WHERE `constraint_schema` = DATABASE()
          AND `table_name` = 'scores'
          AND `constraint_name` = 'ck_scores_semester'
          AND `constraint_type` = 'CHECK'
    ) THEN
        ALTER TABLE `scores`
            ADD CONSTRAINT `ck_scores_semester`
                CHECK (`semester` BETWEEN 1 AND 3);
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM `information_schema`.`statistics`
        WHERE `table_schema` = DATABASE()
          AND `table_name` = 'scores'
          AND `index_name` = 'idx_scores_subject_term'
    ) THEN
        ALTER TABLE `scores`
            ADD INDEX `idx_scores_subject_term`
                (`subject_id`, `academic_year`, `semester`);
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM `information_schema`.`key_column_usage`
        WHERE `constraint_schema` = DATABASE()
          AND `table_name` = 'scores'
          AND `column_name` = 'subject_id'
          AND `referenced_table_schema` = DATABASE()
          AND `referenced_table_name` = 'subjects'
          AND `referenced_column_name` = 'id'
    ) THEN
        ALTER TABLE `scores`
            ADD CONSTRAINT `fk_scores_subject`
                FOREIGN KEY (`subject_id`) REFERENCES `subjects` (`id`)
                ON UPDATE RESTRICT ON DELETE RESTRICT;
    END IF;

    DROP TABLE IF EXISTS `subject_classes`;
    DROP TABLE IF EXISTS `teachers`;

    SELECT 'Simplified academic model migration completed' AS `result`;
END$$

DELIMITER ;

CALL `migrate_simplified_academic_model`();
DROP PROCEDURE IF EXISTS `migrate_simplified_academic_model`;
