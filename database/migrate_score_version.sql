-- Stop all Portal writers and select the Portal database before running this migration.
-- Existing rows start at version 0; rerunning does not reset existing version counters.
DROP PROCEDURE IF EXISTS `migrate_score_version`;

DELIMITER //

CREATE PROCEDURE `migrate_score_version`()
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM `information_schema`.`columns`
        WHERE `table_schema` = DATABASE()
          AND `table_name` = 'scores'
          AND `column_name` = 'version'
    ) THEN
        ALTER TABLE `scores`
            ADD COLUMN `version` BIGINT NOT NULL DEFAULT 0;
    END IF;
END//

DELIMITER ;

CALL `migrate_score_version`();
DROP PROCEDURE `migrate_score_version`;
