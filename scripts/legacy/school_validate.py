"""Read-only validation of the five original score-portal tables; never execute DDL or seed data."""
import argparse
import hashlib
import json
from pathlib import Path
import pymysql

ORIGINAL = ('scores', 'student_classes', 'students', 'subjects', 'users')


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


def validate(db, expected):
    assert str(query(db, 'SELECT @@version')[0][0]).startswith('9.1.0'), 'UNREVIEWED_ENGINE'
    assert query(db, 'SELECT @@lower_case_table_names')[0][0] == 1, 'CASE_SETTING_DRIFT'
    assert fingerprint(db) == expected, 'ORIGINAL_SCHEMA_OR_ROWS_DRIFT'
    actual = {r[0] for r in query(db, "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA='vip_pro'")}
    assert set(ORIGINAL) <= actual, 'MISSING_ORIGINAL_TABLE'
    assert query(db, "SELECT COLUMN_TYPE,IS_NULLABLE,COLUMN_DEFAULT FROM information_schema.COLUMNS "
                     "WHERE TABLE_SCHEMA='vip_pro' AND TABLE_NAME='scores' AND COLUMN_NAME='version'")[0] == ('bigint', 'NO', '0'), 'SCORE_VERSION_DRIFT'
    assert query(db, 'SELECT COUNT(*),COUNT(DISTINCT keycloak_user_id) FROM users')[0] == (6, 6), 'IDENTITY_DRIFT'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['check'])
    parser.add_argument('--config', required=True)
    parser.add_argument('--baseline', required=True)
    args = parser.parse_args()
    cfg = json.loads(Path(args.config).read_text())
    baseline = json.loads(Path(args.baseline).read_text())
    with connect(cfg) as db:
        validate(db, baseline)
    print(json.dumps({'action': args.action, 'status': 'PASS', 'schema_changes': 0,
                      'original_rows': sum(table['rows'] for table in baseline['tables'].values()),
                      'identity_mappings': 6}))


if __name__ == '__main__':
    main()
