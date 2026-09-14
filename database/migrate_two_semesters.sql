-- Restrict an existing scores table to semester 1 and semester 2.
-- The migration stops without changing data when semester 3 rows still exist.
DROP PROCEDURE IF EXISTS `migrate_two_semesters`;

DELIMITER //

CREATE PROCEDURE `migrate_two_semesters`()
BEGIN
    IF EXISTS (
        SELECT 1
        FROM `scores`
        WHERE `semester` NOT BETWEEN 1 AND 2
    ) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'scores with a semester outside 1 and 2 still exist';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM `information_schema`.`table_constraints`
        WHERE `constraint_schema` = DATABASE()
          AND `table_name` = 'scores'
          AND `constraint_name` = 'ck_scores_semester'
          AND `constraint_type` = 'CHECK'
    ) THEN
        ALTER TABLE `scores`
            DROP CHECK `ck_scores_semester`;
    END IF;

    ALTER TABLE `scores`
        ADD CONSTRAINT `ck_scores_semester`
            CHECK (`semester` BETWEEN 1 AND 2);
END//

DELIMITER ;

CALL `migrate_two_semesters`();
DROP PROCEDURE `migrate_two_semesters`;
