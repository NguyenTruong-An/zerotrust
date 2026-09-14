-- Seed 20 complete score rows for the five existing student accounts.
-- Run only after all schema migrations have completed successfully.
-- The script is idempotent: existing scores are kept and only missing rows are inserted.
USE `vip_pro`;

DROP PROCEDURE IF EXISTS `seed_20_sample_scores`;

DELIMITER //

CREATE PROCEDURE `seed_20_sample_scores`()
BEGIN
    DECLARE inserted_scores INT DEFAULT 0;

    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        DROP TEMPORARY TABLE IF EXISTS `sample_score_input`;
        RESIGNAL;
    END;

    START TRANSACTION;

    IF (
        SELECT COUNT(*)
        FROM `users` AS `user_account`
        INNER JOIN `students` AS `student`
            ON `student`.`user_id` = `user_account`.`id`
        WHERE `user_account`.`username` IN (
            'nguyenvana',
            'nguyenvanb',
            'nguyenvanc',
            'nguyenvand',
            'nguyenvanp'
        )
    ) <> 5 THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'one or more sample usernames do not have a student profile';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM `subjects`
        WHERE (`subject_code` = 'ATTT101'
                AND `subject_name` <> 'Cơ sở an toàn thông tin')
           OR (`subject_name` = 'Cơ sở an toàn thông tin'
                AND `subject_code` <> 'ATTT101')
           OR (`subject_code` = 'JAVA101'
                AND `subject_name` <> 'Lập trình Java')
           OR (`subject_name` = 'Lập trình Java'
                AND `subject_code` <> 'JAVA101')
           OR (`subject_code` = 'CSDL101'
                AND `subject_name` <> 'Cơ sở dữ liệu')
           OR (`subject_name` = 'Cơ sở dữ liệu'
                AND `subject_code` <> 'CSDL101')
           OR (`subject_code` = 'MMT101'
                AND `subject_name` <> 'Mạng máy tính')
           OR (`subject_name` = 'Mạng máy tính'
                AND `subject_code` <> 'MMT101')
    ) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'a sample subject code or name is already used by another subject';
    END IF;

    INSERT INTO `subjects` (
        `id`,
        `subject_code`,
        `subject_name`,
        `credits`,
        `description`
    )
    SELECT
        UUID_TO_BIN(UUID()),
        'ATTT101',
        'Cơ sở an toàn thông tin',
        3,
        'Kiến thức nền tảng về bảo đảm và an toàn thông tin.'
    WHERE NOT EXISTS (
        SELECT 1 FROM `subjects` WHERE `subject_code` = 'ATTT101'
    );

    INSERT INTO `subjects` (
        `id`,
        `subject_code`,
        `subject_name`,
        `credits`,
        `description`
    )
    SELECT
        UUID_TO_BIN(UUID()),
        'JAVA101',
        'Lập trình Java',
        3,
        'Lập trình hướng đối tượng và xây dựng ứng dụng bằng Java.'
    WHERE NOT EXISTS (
        SELECT 1 FROM `subjects` WHERE `subject_code` = 'JAVA101'
    );

    INSERT INTO `subjects` (
        `id`,
        `subject_code`,
        `subject_name`,
        `credits`,
        `description`
    )
    SELECT
        UUID_TO_BIN(UUID()),
        'CSDL101',
        'Cơ sở dữ liệu',
        3,
        'Thiết kế, truy vấn và quản trị cơ sở dữ liệu quan hệ.'
    WHERE NOT EXISTS (
        SELECT 1 FROM `subjects` WHERE `subject_code` = 'CSDL101'
    );

    INSERT INTO `subjects` (
        `id`,
        `subject_code`,
        `subject_name`,
        `credits`,
        `description`
    )
    SELECT
        UUID_TO_BIN(UUID()),
        'MMT101',
        'Mạng máy tính',
        3,
        'Nguyên lý mạng, giao thức và mô hình truyền thông máy tính.'
    WHERE NOT EXISTS (
        SELECT 1 FROM `subjects` WHERE `subject_code` = 'MMT101'
    );

    CREATE TEMPORARY TABLE `sample_score_input` (
        `username` VARCHAR(100) NOT NULL,
        `subject_code` VARCHAR(30) NOT NULL,
        `semester` TINYINT UNSIGNED NOT NULL,
        `academic_year` VARCHAR(9) NOT NULL,
        `attendance_score` DECIMAL(4,2) NOT NULL,
        `midterm_score` DECIMAL(4,2) NOT NULL,
        `final_score` DECIMAL(4,2) NOT NULL,
        PRIMARY KEY (`username`, `subject_code`)
    );

    INSERT INTO `sample_score_input` VALUES
        ('nguyenvana', 'ATTT101', 1, '2026-2027', 9.00, 8.50, 9.50),
        ('nguyenvana', 'JAVA101', 1, '2026-2027', 8.00, 8.00, 8.50),
        ('nguyenvana', 'CSDL101', 2, '2026-2027', 7.50, 7.80, 8.00),
        ('nguyenvana', 'MMT101', 2, '2026-2027', 6.50, 7.00, 7.00),

        ('nguyenvanb', 'ATTT101', 1, '2026-2027', 8.50, 8.50, 9.00),
        ('nguyenvanb', 'JAVA101', 1, '2026-2027', 8.00, 7.50, 8.00),
        ('nguyenvanb', 'CSDL101', 2, '2026-2027', 7.00, 7.00, 7.50),
        ('nguyenvanb', 'MMT101', 2, '2026-2027', 6.00, 6.50, 7.00),

        ('nguyenvanc', 'ATTT101', 1, '2026-2027', 7.50, 8.00, 8.50),
        ('nguyenvanc', 'JAVA101', 1, '2026-2027', 7.00, 7.50, 8.00),
        ('nguyenvanc', 'CSDL101', 2, '2026-2027', 6.50, 6.50, 7.00),
        ('nguyenvanc', 'MMT101', 2, '2026-2027', 5.50, 6.00, 6.50),

        ('nguyenvand', 'ATTT101', 1, '2026-2027', 6.00, 6.00, 6.50),
        ('nguyenvand', 'JAVA101', 1, '2026-2027', 5.50, 5.50, 6.00),
        ('nguyenvand', 'CSDL101', 2, '2026-2027', 5.00, 5.00, 5.50),
        ('nguyenvand', 'MMT101', 2, '2026-2027', 3.00, 3.50, 3.50),

        ('nguyenvanp', 'ATTT101', 1, '2026-2027', 9.50, 9.00, 9.50),
        ('nguyenvanp', 'JAVA101', 1, '2026-2027', 8.50, 8.50, 8.50),
        ('nguyenvanp', 'CSDL101', 2, '2026-2027', 7.50, 7.00, 7.50),
        ('nguyenvanp', 'MMT101', 2, '2026-2027', 4.00, 4.00, 4.00);

    INSERT INTO `scores` (
        `id`,
        `student_id`,
        `subject_id`,
        `semester`,
        `academic_year`,
        `attendance_score`,
        `midterm_score`,
        `final_score`,
        `total_score`,
        `grade`
    )
    SELECT
        UUID_TO_BIN(UUID()),
        `student`.`id`,
        `subject`.`id`,
        `calculated`.`semester`,
        `calculated`.`academic_year`,
        `calculated`.`attendance_score`,
        `calculated`.`midterm_score`,
        `calculated`.`final_score`,
        `calculated`.`total_score`,
        CASE
            WHEN `calculated`.`total_score` >= 9.0 THEN 'A+'
            WHEN `calculated`.`total_score` >= 8.5 THEN 'A'
            WHEN `calculated`.`total_score` >= 7.8 THEN 'B+'
            WHEN `calculated`.`total_score` >= 7.0 THEN 'B'
            WHEN `calculated`.`total_score` >= 6.3 THEN 'C+'
            WHEN `calculated`.`total_score` >= 5.5 THEN 'C'
            WHEN `calculated`.`total_score` >= 4.8 THEN 'D+'
            WHEN `calculated`.`total_score` >= 4.0 THEN 'D'
            ELSE 'F'
        END
    FROM (
        SELECT
            `input`.*,
            ROUND(
                ((`input`.`midterm_score` * 0.70
                    + `input`.`attendance_score` * 0.30) * 0.30)
                    + `input`.`final_score` * 0.70,
                1
            ) AS `total_score`
        FROM `sample_score_input` AS `input`
    ) AS `calculated`
    INNER JOIN `users` AS `user_account`
        ON `user_account`.`username` = `calculated`.`username`
    INNER JOIN `students` AS `student`
        ON `student`.`user_id` = `user_account`.`id`
    INNER JOIN `subjects` AS `subject`
        ON `subject`.`subject_code` = `calculated`.`subject_code`
    LEFT JOIN `scores` AS `existing_score`
        ON `existing_score`.`student_id` = `student`.`id`
       AND `existing_score`.`subject_id` = `subject`.`id`
    WHERE `existing_score`.`id` IS NULL;

    SET inserted_scores = ROW_COUNT();

    COMMIT;
    DROP TEMPORARY TABLE `sample_score_input`;

    SELECT
        inserted_scores AS `inserted_scores`,
        20 - inserted_scores AS `already_existing_scores`;

    SELECT
        `user_account`.`username`,
        `student`.`student_code`,
        `subject`.`subject_code`,
        `subject`.`subject_name`,
        `score`.`semester`,
        `score`.`academic_year`,
        `score`.`attendance_score`,
        `score`.`midterm_score`,
        `score`.`final_score`,
        `score`.`total_score`,
        `score`.`grade`
    FROM `scores` AS `score`
    INNER JOIN `students` AS `student`
        ON `student`.`id` = `score`.`student_id`
    INNER JOIN `users` AS `user_account`
        ON `user_account`.`id` = `student`.`user_id`
    INNER JOIN `subjects` AS `subject`
        ON `subject`.`id` = `score`.`subject_id`
    WHERE `user_account`.`username` IN (
            'nguyenvana',
            'nguyenvanb',
            'nguyenvanc',
            'nguyenvand',
            'nguyenvanp'
        )
      AND `subject`.`subject_code` IN (
            'ATTT101',
            'JAVA101',
            'CSDL101',
            'MMT101'
        )
    ORDER BY `user_account`.`username`, `score`.`semester`, `subject`.`subject_code`;
END//

DELIMITER ;

CALL `seed_20_sample_scores`();
DROP PROCEDURE IF EXISTS `seed_20_sample_scores`;
