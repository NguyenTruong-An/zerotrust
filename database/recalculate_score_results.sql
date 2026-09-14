-- Run once after deploying automatic score calculation if scores already contain data.
-- New and updated scores are calculated by ScoreAdministrationServiceImpl.
START TRANSACTION;

UPDATE `scores`
SET `total_score` = ROUND(
        ((`midterm_score` * 0.70 + `attendance_score` * 0.30) * 0.30)
            + `final_score` * 0.70,
        1
    ),
    `grade` = CASE
        WHEN ROUND(((`midterm_score` * 0.70 + `attendance_score` * 0.30) * 0.30) + `final_score` * 0.70, 1) >= 9.0 THEN 'A+'
        WHEN ROUND(((`midterm_score` * 0.70 + `attendance_score` * 0.30) * 0.30) + `final_score` * 0.70, 1) >= 8.5 THEN 'A'
        WHEN ROUND(((`midterm_score` * 0.70 + `attendance_score` * 0.30) * 0.30) + `final_score` * 0.70, 1) >= 7.8 THEN 'B+'
        WHEN ROUND(((`midterm_score` * 0.70 + `attendance_score` * 0.30) * 0.30) + `final_score` * 0.70, 1) >= 7.0 THEN 'B'
        WHEN ROUND(((`midterm_score` * 0.70 + `attendance_score` * 0.30) * 0.30) + `final_score` * 0.70, 1) >= 6.3 THEN 'C+'
        WHEN ROUND(((`midterm_score` * 0.70 + `attendance_score` * 0.30) * 0.30) + `final_score` * 0.70, 1) >= 5.5 THEN 'C'
        WHEN ROUND(((`midterm_score` * 0.70 + `attendance_score` * 0.30) * 0.30) + `final_score` * 0.70, 1) >= 4.8 THEN 'D+'
        WHEN ROUND(((`midterm_score` * 0.70 + `attendance_score` * 0.30) * 0.30) + `final_score` * 0.70, 1) >= 4.0 THEN 'D'
        ELSE 'F'
    END
WHERE `attendance_score` IS NOT NULL
  AND `midterm_score` IS NOT NULL
  AND `final_score` IS NOT NULL;

UPDATE `scores`
SET `total_score` = NULL,
    `grade` = NULL
WHERE `attendance_score` IS NULL
   OR `midterm_score` IS NULL
   OR `final_score` IS NULL;

COMMIT;
