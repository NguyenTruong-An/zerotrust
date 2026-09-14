-- Enforce one score record per student and subject on an existing database.
-- The migration stops without deleting data when duplicate rows already exist.
DROP PROCEDURE IF EXISTS `migrate_unique_score_per_subject`;

DELIMITER //

CREATE PROCEDURE `migrate_unique_score_per_subject`()
BEGIN
    IF EXISTS (
        SELECT 1
        FROM `scores`
        GROUP BY `student_id`, `subject_id`
        HAVING COUNT(*) > 1
    ) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'duplicate scores exist for the same student and subject';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM `information_schema`.`statistics`
        WHERE `table_schema` = DATABASE()
          AND `table_name` = 'scores'
          AND `index_name` = 'uk_scores_student_subject'
    ) THEN
        ALTER TABLE `scores`
            ADD CONSTRAINT `uk_scores_student_subject`
                UNIQUE (`student_id`, `subject_id`);
    END IF;

    IF EXISTS (
        SELECT 1
        FROM `information_schema`.`statistics`
        WHERE `table_schema` = DATABASE()
          AND `table_name` = 'scores'
          AND `index_name` = 'uk_scores_student_subject_term'
    ) THEN
        ALTER TABLE `scores`
            DROP INDEX `uk_scores_student_subject_term`;
    END IF;
END//

DELIMITER ;

CALL `migrate_unique_score_per_subject`();
DROP PROCEDURE `migrate_unique_score_per_subject`;
