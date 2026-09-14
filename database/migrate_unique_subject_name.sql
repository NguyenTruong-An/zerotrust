-- Ensure that one subject name can only belong to one subject code.
-- Resolve any duplicates reported by this migration before running it again.
DROP PROCEDURE IF EXISTS `migrate_unique_subject_name`;

DELIMITER //

CREATE PROCEDURE `migrate_unique_subject_name`()
BEGIN
    IF EXISTS (
        SELECT 1
        FROM `subjects`
        GROUP BY LOWER(TRIM(`subject_name`))
        HAVING COUNT(*) > 1
    ) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'duplicate subject names exist; remove or rename them first';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM `information_schema`.`statistics`
        WHERE `table_schema` = DATABASE()
          AND `table_name` = 'subjects'
          AND `index_name` = 'uk_subjects_name'
    ) THEN
        ALTER TABLE `subjects`
            ADD CONSTRAINT `uk_subjects_name` UNIQUE (`subject_name`);
    END IF;
END//

DELIMITER ;

CALL `migrate_unique_subject_name`();
DROP PROCEDURE `migrate_unique_subject_name`;
