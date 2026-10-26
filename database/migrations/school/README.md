# Additive School legacy migration

V20261026_01 adds teachers, teaching_assignments, schedule_entries and the
school_schema_history ledger on a new restored MySQL9.1.0 copy. It creates no teacher,
assignment, schedule, user or score rows. UUID storage, RESTRICT FKs, uniqueness and
the weekday/time CHECK follow the published entities/schema. Foreign-key supporting
indexes are provided by the unique key or InnoDB's FK index creation.

Run scripts/legacy/school_migrate.py preflight before execution; apply requires the
owner-approved project and exact migration SHA256. The connection must be the new
school/vip_pro service with TLS certificate/hostname verification. Preflight compares
all original table/row hashes, columns via normalized SHOW CREATE, scores.version,
case setting and six distinct identity bytes; it rejects partial/existing teaching tables.

Postflight compares the five original schemas/49 business rows byte-for-value, five new
RESTRICT FKs and one matching ledger record. All three teaching tables must remain empty.
One ledger metadata row is additional; it is not a new business record.

Do not run schema.sql, fresh-only migrate_teacher_assignment_schedule.sql, fixture seeds,
recalculate_score_results.sql or migrate_score_version.sql on this reviewed legacy data.
The version column already exists. SQL recalculation rewrites grades and is outside the plan.

MySQL CREATE TABLE commits independently. A failure after any statement is a partial
migration: stop candidate writers and retain evidence. Restore the verified logical dump
to a clean, reviewed candidate destination; do not DROP existing business tables, reverse
DDL or mark a failed migration successful. This migration has not yet run against a
persistent database; real MySQL acceptance is part of the consolidated execution approval.
