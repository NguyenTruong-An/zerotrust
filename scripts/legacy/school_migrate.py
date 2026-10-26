"""Reviewed additive migration on a new approved copy; never repair/seed a legacy source."""
import argparse
import hashlib
import json
from pathlib import Path
import pymysql

ORIGINAL = ('scores', 'student_classes', 'students', 'subjects', 'users')
ADDITIONS = ('teachers', 'teaching_assignments', 'schedule_entries')
VERSION = '20261026_01'


def connect(config):
    assert config['host'] == 'school' and config['database'] == 'vip_pro', 'UNAPPROVED_DESTINATION'
    return pymysql.connect(host='school', port=3306, database='vip_pro', user=config['username'],
                           password=config['password'], charset='utf8mb4', autocommit=True,
                           ssl_ca=config['ca'], ssl_verify_cert=True, ssl_verify_identity=True)


def query(db, sql, args=()):
    with db.cursor() as cursor:
        cursor.execute(sql, args)
        return cursor.fetchall()


def fingerprint(db):
    result = {'tables': {}, 'ddl': {}}
    for table in ORIGINAL:
        cols = [r[0] for r in query(db, "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE "
                                   "TABLE_SCHEMA='vip_pro' AND TABLE_NAME=%s ORDER BY ORDINAL_POSITION", (table,))]
        assert cols, 'MISSING_ORIGINAL_TABLE'
        expr = ','.join("'" + c + "',IFNULL(HEX(CAST(`" + c + "` AS BINARY)),NULL)" for c in cols)
        rows = sorted(r[0] for r in query(db, 'SELECT SHA2(CAST(JSON_OBJECT(' + expr +
                                          ') AS CHAR),256) FROM `' + table + '`'))
        result['tables'][table] = {'rows': len(rows), 'sha256': hashlib.sha256('\n'.join(rows).encode()).hexdigest()}
        ddl = query(db, 'SHOW CREATE TABLE `' + table + '`')[0][1]
        result['ddl'][table] = ddl.replace(' CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci',
                                         ' COLLATE utf8mb4_unicode_ci')
    return result


def preflight(db, expected):
    assert str(query(db, 'SELECT @@version')[0][0]).startswith('9.1.0'), 'UNREVIEWED_ENGINE'
    assert query(db, 'SELECT @@lower_case_table_names')[0][0] == 1, 'CASE_SETTING_DRIFT'
    assert fingerprint(db) == expected, 'ORIGINAL_SCHEMA_OR_ROWS_DRIFT'
    actual = {r[0] for r in query(db, "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA='vip_pro'")}
    assert actual == set(ORIGINAL), 'NONEMPTY_OR_PARTIALLY_MIGRATED_DESTINATION'
    assert query(db, "SELECT COLUMN_TYPE,IS_NULLABLE,COLUMN_DEFAULT FROM information_schema.COLUMNS "
                     "WHERE TABLE_SCHEMA='vip_pro' AND TABLE_NAME='scores' AND COLUMN_NAME='version'")[0] == ('bigint', 'NO', '0'), 'SCORE_VERSION_DRIFT'
    assert query(db, 'SELECT COUNT(*),COUNT(DISTINCT keycloak_user_id) FROM users')[0] == (6, 6), 'IDENTITY_DRIFT'


def postflight(db, expected, checksum):
    assert fingerprint(db) == expected, 'STOP_ORIGINAL_ROWS_OR_SCHEMA_CHANGED'
    for table in ADDITIONS:
        assert query(db, 'SELECT COUNT(*) FROM `' + table + '`')[0][0] == 0, 'UNAPPROVED_OWNERSHIP_SEED'
    assert query(db, 'SELECT version,checksum FROM school_schema_history') == ((VERSION, checksum),), 'HISTORY_DRIFT'
    expected_fks = {'fk_teachers_user', 'fk_assignments_teacher', 'fk_assignments_class',
                    'fk_assignments_subject', 'fk_schedule_assignment'}
    actual = {r[0] for r in query(db, "SELECT CONSTRAINT_NAME FROM information_schema.REFERENTIAL_CONSTRAINTS "
                                  "WHERE CONSTRAINT_SCHEMA='vip_pro' AND TABLE_NAME IN "
                                  "('teachers','teaching_assignments','schedule_entries') AND "
                                  "DELETE_RULE='RESTRICT' AND UPDATE_RULE='RESTRICT'")}
    assert actual == expected_fks, 'FK_CONTRACT_DRIFT'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['preflight', 'apply', 'postflight'])
    parser.add_argument('--config', required=True)
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--migration', required=True)
    parser.add_argument('--approval')
    args = parser.parse_args()
    cfg = json.loads(Path(args.config).read_text())
    baseline = json.loads(Path(args.baseline).read_text())
    migration = Path(args.migration).read_bytes()
    checksum = hashlib.sha256(migration).hexdigest()
    if args.action == 'apply':
        assert args.approval, 'OWNER_EXECUTION_APPROVAL_REQUIRED'
        approval = json.loads(Path(args.approval).read_text())
        assert approval.get('approved') is True and approval['project'] == cfg['project'], 'APPROVAL_MISMATCH'
        assert approval['school_migration_sha256'] == checksum, 'UNAPPROVED_SCRIPT_CHANGE'
    with connect(cfg) as db:
        if args.action in ('preflight', 'apply'):
            preflight(db, baseline)
        if args.action == 'apply':
            text = '\n'.join(l for l in migration.decode().splitlines() if not l.lstrip().startswith('--'))
            # Reviewed file contains only these four CREATE TABLE statements, no dynamic SQL or seeds.
            statements = [s.strip() for s in text.split(';') if s.strip()]
            assert len(statements) == 4 and all(s.startswith('CREATE TABLE ') for s in statements)
            for statement in statements:
                query(db, statement)
            query(db, 'INSERT INTO school_schema_history(version,checksum) VALUES(%s,%s)', (VERSION, checksum))
        if args.action in ('apply', 'postflight'):
            postflight(db, baseline, checksum)
    print(json.dumps({'action': args.action, 'status': 'PASS', 'migration_sha256': checksum,
                      'original_rows': 49, 'identity_mappings': 6, 'new_teacher_owners': 0}))


if __name__ == '__main__':
    main()
