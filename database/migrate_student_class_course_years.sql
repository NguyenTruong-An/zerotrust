-- Rename the student class academic-year field to course years without losing data.
-- Score academic_year is intentionally unchanged because it represents one school year.
DROP PROCEDURE IF EXISTS `migrate_student_class_course_years`;

DELIMITER //

CREATE PROCEDURE `migrate_student_class_course_years`()
BEGIN
    DECLARE has_academic_year INT DEFAULT 0;
    DECLARE has_course_years INT DEFAULT 0;

    SELECT COUNT(*) INTO has_academic_year
    FROM `information_schema`.`columns`
    WHERE `table_schema` = DATABASE()
      AND `table_name` = 'student_classes'
      AND `column_name` = 'academic_year';

    SELECT COUNT(*) INTO has_course_years
    FROM `information_schema`.`columns`
    WHERE `table_schema` = DATABASE()
      AND `table_name` = 'student_classes'
      AND `column_name` = 'course_years';

    IF has_academic_year = 1 AND has_course_years = 0 THEN
        ALTER TABLE `student_classes`
            CHANGE COLUMN `academic_year` `course_years` VARCHAR(9) NOT NULL
                COMMENT 'Example: 2022-2027';
    ELSEIF has_academic_year = 1 AND has_course_years = 1 THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'student_classes has both academic_year and course_years; resolve the duplicate columns first';
    ELSEIF has_academic_year = 0 AND has_course_years = 0 THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'student_classes has neither academic_year nor course_years';
    ELSE
        ALTER TABLE `student_classes`
            MODIFY COLUMN `course_years` VARCHAR(9) NOT NULL
                COMMENT 'Example: 2022-2027';
    END IF;
END//

DELIMITER ;

CALL `migrate_student_class_course_years`();
DROP PROCEDURE `migrate_student_class_course_years`;
