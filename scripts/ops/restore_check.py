"""Rehearse a cold lab backup on fresh volumes and networkless containers."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import time
import uuid

import backup
import relocate_runtime as layout
import zt

SCHEMAS = {'school': 'vip_pro', 'risk-db': 'risk_db', 'keycloak-db': 'keycloak_legacy'}
EXPECTED = {'school': {'students', 'scores'}, 'risk-db': {'flyway_schema_history', 'authentication_success_events'},
            'keycloak-db': {'REALM', 'USER_ENTITY', 'CREDENTIAL', 'CLIENT'}}


def docker(*args, timeout=180):
    result = subprocess.run(['docker', *args], capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'Docker {args[0]} failed (exit {result.returncode}); inspect isolated resource locally')
    return result.stdout.decode('utf-8', errors='replace').strip()


def verify_archives(source):
    manifest = json.loads((source / 'manifest.json').read_text(encoding='utf-8'))
    files = {f'{s}.tar.gz' for s in zt.DATA_VOLUMES} | {'runtime.tar.gz'}
    if (manifest['status'] != 'archive_verified' or manifest['project'] != zt.PROJECT
            or set(manifest['files']) != files or set(manifest['images']) != set(zt.SERVICES)):
        raise RuntimeError('Backup manifest incomplete or for another project')
    for name in sorted(files):
        path = source / name
        expected = manifest['files'][name]
        if path.stat().st_size != expected['bytes'] or backup.sha256(path) != expected['sha256']:
            raise RuntimeError(f'Archive hash or length mismatch: {name}')
        with tarfile.open(path, 'r:gz') as archive:
            if sum(1 for _ in archive) != expected['members']:
                raise RuntimeError(f'Archive member count mismatch: {name}')
    with tarfile.open(source / 'runtime.tar.gz', 'r:gz') as archive:
        with archive.extractfile('runtime/images.private.yaml') as stream:
            lock = json.load(stream)
    if {s: v['image'] for s, v in lock['services'].items()} != manifest['images']:
        raise RuntimeError('Backed-up runtime image lock differs from the backup manifest')
    return manifest


def extract_db_configs(source, destination):
    # Copy only the backed-up DB configs and TLS files, into a new private tree.
    with tarfile.open(source / 'runtime.tar.gz', 'r:gz') as archive:
        for member in archive:
            parts = PurePosixPath(member.name).parts
            if len(parts) < 2 or parts[0] != 'runtime' or parts[1] not in zt.DATA_VOLUMES:
                continue
            if any(part in ('.', '..') or ':' in part or '\\' in part for part in parts):
                raise RuntimeError('Unsafe runtime archive path')
            target = destination.joinpath(*parts[1:])
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as stream, target.open('xb') as output:
                    shutil.copyfileobj(stream, output)
            else:
                raise RuntimeError('Unexpected runtime archive member type')
    for service in zt.DATA_VOLUMES:
        if any(not (destination / service / file).is_file() for file in zt.REQUIRED_FILES[service]):
            raise RuntimeError(f'Missing backed-up configuration: {service}')


def sql(container, query):
    return docker('exec', container, 'sh', '-ec',
                  'umask 077; cfg=$(mktemp); trap \'rm -f "$cfg"\' EXIT; '
                  'cp /run/demo/client.cnf "$cfg"; '
                  'mysql --defaults-extra-file="$cfg" --batch --skip-column-names -e "$1"',
                  'mysql-check', query).splitlines()


def mysql_state(container, schema):
    tables = sql(container, f"SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA='{schema}' "
                            "AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME")
    if not tables or any(not re.fullmatch(r'[A-Za-z0-9_]+', table) for table in tables):
        raise RuntimeError(f'Invalid or empty restored schema: {schema}')
    names = [f'`{schema}`.`{table}`' for table in tables]
    metadata = sql(container, 'SELECT TABLE_NAME,COLUMN_NAME,ORDINAL_POSITION,COLUMN_TYPE,IS_NULLABLE,'
                             'COLUMN_KEY,EXTRA FROM information_schema.COLUMNS '
                             f"WHERE TABLE_SCHEMA='{schema}' ORDER BY TABLE_NAME,ORDINAL_POSITION")
    counts = sql(container, ';'.join(f"SELECT '{table}',COUNT(*) FROM {name}" for table, name in zip(tables, names)))
    checksums = sql(container, 'CHECKSUM TABLE ' + ','.join(names) + ' EXTENDED')
    if (len(counts) != len(tables) or len(checksums) != len(tables)
            or any(not row.split('\t')[-1].isdigit() for row in counts + checksums)):
        raise RuntimeError('Incomplete table readability/checksum evidence')
    migrations = []
    if 'flyway_schema_history' in tables:
        migrations = sql(container, f'SELECT installed_rank,version,checksum,success FROM `{schema}`.flyway_schema_history ORDER BY installed_rank')
        if not migrations or any(row.split('\t')[-1] != '1' for row in migrations):
            raise RuntimeError('Flyway history contains no successful baseline or contains failures')
    return {'tables': tables, 'columns': metadata, 'counts': counts, 'checksums': checksums,
            'migrations': migrations}


def redis_state(container):
    result = docker('exec', container, 'sh', '-ec',
                    'export REDISCLI_AUTH="$(cat /run/demo/redis-password)"; '
                    'redis-cli --tls --cacert /run/demo/ca.crt -h redis PING; '
                    'redis-cli --tls --cacert /run/demo/ca.crt -h redis INFO keyspace')
    lines = result.splitlines()
    if not lines or lines[0] != 'PONG' or '# Keyspace' not in lines:
        raise RuntimeError('Redis TLS/auth/read probe failed')
    return sorted(line for line in lines if re.match(r'db\d+:', line))


def wait_healthy(container):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        state = zt.docker_json('inspect', container)[0]['State']
        if not state['Running']:
            raise RuntimeError('Isolated database exited during startup')
        if state.get('Health', {}).get('Status') == 'healthy':
            return
        time.sleep(2)
    raise RuntimeError('Isolated database health check timed out')


def resource_contract(rows):
    services = zt.summarize(rows)['services']
    return {s: (i['id'], i['image_id'], sorted(i['mounts'], key=lambda m: m['Destination']),
                sorted(i['networks'])) for s, i in services.items()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('backup', type=Path)
    args = parser.parse_args(argv)
    source = args.backup.resolve(strict=True)
    rows = zt.collect()
    before = resource_contract(rows)
    manifest = verify_archives(source)
    for service, identifier in manifest['images'].items():
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', identifier):
            raise RuntimeError('Backup must pin immutable image IDs')
        if zt.docker_json('image', 'inspect', identifier)[0]['Id'] != identifier:
            raise RuntimeError(f'Backup image unavailable: {service}')
        if service in zt.DATA_VOLUMES and rows[service]['Image'] != identifier:
            raise RuntimeError(f'Current DB command/health contract may differ from backup image: {service}')
    run_id = f'zt-restore-{dt.datetime.now(dt.timezone.utc):%Y%m%d%H%M%S}-{uuid.uuid4().hex[:6]}'
    state = zt.ROOT.parent / 'backups' / 'verification' / run_id
    layout.secure_directory(state)
    evidence = {'backup': source.name, 'run': run_id, 'archive_integrity': 'PASS',
                'full_application_recovery': 'NOT VERIFIED', 'services': {}}
    print(f'Archive integrity PASS; isolated resources use prefix {run_id}', flush=True)
    try:
        extract_db_configs(source, state)
        for service in zt.DATA_VOLUMES:
            live = rows[service]
            container = volume = f'{run_id}-{service}'
            summary = evidence['services'][service] = {'volume': volume, 'container': container}
            destination = '/data' if service == 'redis' else '/var/lib/mysql'
            docker('volume', 'create', '--label', f'zerotrust.restore={run_id}', volume)
            docker('run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
                   '--entrypoint', '/opt/tools/bin/python',
                   '--mount', f'type=volume,src={volume},dst=/target,volume-nocopy',
                   '--mount', f'type=bind,src={source},dst=/backup,readonly',
                   '--mount', f'type=bind,src={zt.ROOT / "scripts/legacy/archive_volume.py"},dst=/archive.py,readonly',
                   manifest['images']['crl'], '/archive.py', 'unpack', f'/backup/{service}.tar.gz', '/target')
            summary['restore_execution'] = 'PASS'
            health = live['Config']['Healthcheck']['Test']
            entrypoint = live['Config']['Entrypoint']
            if len(entrypoint) != 1 or health[0] != 'CMD-SHELL':
                raise RuntimeError('Unsupported DB startup contract')
            command = [*entrypoint, *live['Config']['Cmd']]
            if service in SCHEMAS:
                option = '--defaults-extra-file=/run/demo/server.cnf'
                if option not in command:
                    raise RuntimeError('Unsupported MySQL configuration path')
                command[command.index(option)] = '--defaults-extra-file=/tmp/restore-check-server.cnf'
                # NTFS bind mounts can present mode 0777, which MySQL rejects.
                command = ['sh', '-ec', 'cp /run/demo/server.cnf /tmp/restore-check-server.cnf; '
                           'chmod 0644 /tmp/restore-check-server.cnf; exec "$@"', 'restore-entrypoint', *command]
            docker('create', '--pull', 'never', '--name', container, '--network', 'none',
                   '--hostname', service, '--add-host', f'{service}:127.0.0.1',
                   '--label', f'zerotrust.restore={run_id}', '--restart', 'no',
                   '--memory', str(live['HostConfig']['Memory']),
                   '--health-cmd', health[1], '--health-interval', '3s',
                   '--entrypoint', command[0],
                   '--mount', f'type=volume,src={volume},dst={destination},volume-nocopy',
                   '--mount', f'type=bind,src={state / service},dst=/run/demo,readonly',
                   manifest['images'][service], *command[1:])
            instance = zt.docker_json('inspect', container)[0]
            if (instance['HostConfig']['NetworkMode'] != 'none' or instance['HostConfig']['PortBindings']
                    or instance['Image'] != manifest['images'][service]
                    or {m['Name'] for m in instance['Mounts'] if m['Type'] == 'volume'} != {volume}):
                raise RuntimeError('Restore container isolation verification failed')
            docker('start', container)
            try:
                wait_healthy(container)
                if service in SCHEMAS:
                    restored = mysql_state(container, SCHEMAS[service])
                    if not EXPECTED[service] <= set(restored['tables']):
                        raise RuntimeError(f'Missing expected tables: {service}')
                    current = mysql_state(live['Id'], SCHEMAS[service])
                    summary.update(tables=len(restored['tables']), migration_entries=len(restored['migrations']),
                                   rows=sum(int(row.split('\t')[-1]) for row in restored['counts']),
                                   checks={key: restored[key] == current[key] for key in restored})
                    summary['different_row_counts'] = sorted(
                        {row.split('\t')[0] for row in set(restored['counts']) ^ set(current['counts'])})
                    summary['different_checksums'] = sorted(
                        {row.split('\t')[0] for row in set(restored['checksums']) ^ set(current['checksums'])})
                    consistent = all(summary['checks'].values())
                else:
                    restored, current = redis_state(container), redis_state(live['Id'])
                    summary.update(restored_keyspace_empty=not restored, canonical_keyspace_empty=not current)
                    # INFO keyspace alone is insufficient to prove matching nonempty values.
                    consistent = not restored and not current
                summary['database_readability'] = 'PASS'
                summary['data_consistency'] = 'PASS' if consistent else 'PARTIAL'
            finally:
                docker('stop', '--timeout', '35', container, timeout=60)
            print(f'{service}: restore PASS, readability PASS, consistency {summary["data_consistency"]}', flush=True)
    finally:
        evidence['canonical_identity_image_mounts_unchanged'] = before == resource_contract(zt.collect())
        path = state / 'verification.json'
        path.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
        print(f'Evidence: {path}', flush=True)
    if not evidence['canonical_identity_image_mounts_unchanged']:
        raise RuntimeError('Canonical resources changed during verification')


if __name__ == '__main__':
    main()
