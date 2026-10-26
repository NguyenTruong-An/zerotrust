-- Maintenance only: NOT part of legacy integration; rewrites grades. Requires separate controlled authorization.
-- Run once after deploying automatic score calculation if scores already contain data.
-- New and updated scores are calculated by ScoreAdministrationServiceImpl.
-- Apply migrate_score_version.sql first; SQL writes must advance the optimistic lock version.
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
    END,
    `version` = `version` + 1
WHERE `attendance_score` IS NOT NULL
  AND `midterm_score` IS NOT NULL
  AND `final_score` IS NOT NULL;

UPDATE `scores`
SET `total_score` = NULL,
    `grade` = NULL,
    `version` = `version` + 1
WHERE `attendance_score` IS NULL
   OR `midterm_score` IS NULL
   OR `final_score` IS NULL;

COMMIT;
