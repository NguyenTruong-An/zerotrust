"""Operate the existing lab deployment; inventory output contains no secret values."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts' / 'legacy'))
import operate as legacy

PROJECT = legacy.PROJECT
SERVICES = tuple(legacy.ORDER)
DATA_VOLUMES = {'school': 'school-data', 'risk-db': 'risk-db-data',
                'keycloak-db': 'keycloak-db-data', 'redis': 'redis-data'}
REQUIRED_FILES = {
    'backend': ('application.properties', 'jvm.args'),
    'risk': ('application.properties', 'jvm.args', 'legacy-policy.env'),
    'gateway': ('application.properties', 'jvm.args'),
    'keycloak': ('keycloak.conf', 'jvm.args'),
    'school': ('server.cnf', 'client.cnf', 'root-password'),
    'risk-db': ('server.cnf', 'client.cnf', 'root-password'),
    'keycloak-db': ('server.cnf', 'client.cnf', 'root-password'),
    'redis': ('redis.conf', 'redis-password', 'ca.crt'),
    'crl': ('ca.crl', 'ca.crt'),
}


def host_path(source, *, windows=None):
    """Docker Desktop sometimes reports Linux-VM paths for Windows bind sources."""
    if windows is None:
        windows = sys.platform == 'win32'
    if windows:
        match = re.fullmatch(r'/(?:run/desktop/mnt/host|host_mnt)/([a-zA-Z])/(.*)', source)
        if match:
            source = f'{match[1].upper()}:/{match[2]}'
    return Path(source)


def docker_json(*args):
    result = subprocess.run(['docker', *args], capture_output=True, text=True,
                            encoding='utf-8', timeout=30)
    if result.returncode:
        raise RuntimeError('Docker query failed. Check Docker Desktop, permissions and container names.')
    return json.loads(result.stdout)


def validate_identity(service, info):
    labels = info['Config'].get('Labels') or {}
    if (labels.get('app.owner') != PROJECT
            or labels.get('com.docker.compose.project') != PROJECT
            or labels.get('com.docker.compose.service') != service
            or info.get('Name', '').lstrip('/') != f'{PROJECT}-{service}'):
        raise RuntimeError(f'{service}: container identity does not match the lab deployment')


def collect():
    rows = {}
    for service in SERVICES:
        try:
            info = docker_json('inspect', f'{PROJECT}-{service}')[0]
        except RuntimeError:
            try:
                docker_json('info', '--format', '{{json .}}')
            except RuntimeError:
                raise RuntimeError('Docker Engine unavailable. Open Docker Desktop, wait for it to start, and retry.') from None
            raise RuntimeError(f'{service}: lab container unavailable. Confirm the canonical project and run zt.cmd config-check.') from None
        validate_identity(service, info)
        rows[service] = info
    return rows


def summarize(rows):
    """Allowlist metadata only: never serialize Config.Env or file contents."""
    result = {}
    for service, info in rows.items():
        labels = info['Config'].get('Labels') or {}
        result[service] = {
            'id': info['Id'], 'image_id': info['Image'],
            'image': info['Config']['Image'],
            'status': info['State']['Status'],
            'health': (info['State'].get('Health', {}).get('Status', 'not_configured')
                       if info['State'].get('Running') else 'not_running'),
            'stored_health': info['State'].get('Health', {}).get('Status', 'not_configured'),
            'compose_files_at_creation': labels.get('com.docker.compose.project.config_files', ''),
            'mounts': [{key: mount.get(key) for key in
                        ('Type', 'Name', 'Source', 'Destination', 'RW')}
                       for mount in info.get('Mounts', [])],
            'port_bindings': info['HostConfig'].get('PortBindings') or {},
            'networks': list(info['NetworkSettings'].get('Networks', {})),
        }
    return {'environment': 'lab', 'project': PROJECT, 'source_root': str(ROOT),
            'services': result}


def diagnose(rows):
    errors, warnings = [], []
    for service, info in rows.items():
        mounts = info.get('Mounts', [])
        target = '/public-ca' if service == 'crl' else '/run/demo'
        runtime = next((m for m in mounts if m['Destination'] == target and m['Type'] == 'bind'), None)
        if service in REQUIRED_FILES:
            if runtime is None:
                errors.append(f'{service}: missing runtime mount {target}')
            else:
                root = host_path(runtime['Source'])
                for filename in REQUIRED_FILES[service]:
                    if not (root / filename).is_file():
                        errors.append(f'{service}: missing runtime file {filename}')
        for mount in mounts:
            if mount['Type'] == 'bind' and not host_path(mount['Source']).exists():
                errors.append(f'{service}: bind source is missing: {mount["Source"]}')
        if service in DATA_VOLUMES:
            expected = f'{PROJECT}_{DATA_VOLUMES[service]}'
            destination = '/data' if service == 'redis' else '/var/lib/mysql'
            if not any(m['Type'] == 'volume' and m.get('Name') == expected
                       and m['Destination'] == destination for m in mounts):
                errors.append(f'{service}: expected volume {expected} at {destination}; check the original volume before starting')
        if not info['State'].get('Running'):
            warnings.append(f'{service}: stopped; stored health is historical')
        elif info['State'].get('Health', {}).get('Status') != 'healthy':
            warnings.append(f'{service}: running but not healthy')
        files = (info['Config'].get('Labels') or {}).get('com.docker.compose.project.config_files', '')
        for filename in files.split(','):
            if filename and not Path(filename).is_file():
                warnings.append(f'{service}: historical Compose path missing: {filename}')
    return {'errors': errors, 'warnings': warnings,
            'scope': 'Identity, bind paths, required configuration filenames and volume mapping; '
                     'does not validate secret values, TLS expiry, database contents or browser flows.'}


def check_configuration(rows):
    import relocate_runtime as layout
    runtime = ROOT.parent / 'runtime' / 'lab'
    lock = runtime / 'images.private.yaml'
    env = runtime / 'compose.private.env'
    for path in (lock, env):
        if not path.is_file():
            raise RuntimeError(f'Missing lab configuration: {path}; recover the reviewed private configuration')
    prefix = layout.compose([ROOT / 'compose.lab.yaml', lock], env)
    model = json.loads(layout.run(prefix + ['config', '--format', 'json']))
    layout.validate_model(model, rows)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('status', 'inventory', 'doctor', 'config-check', 'start', 'stop', 'logs',
                                           'smoke', 'tls-check', 'renew-crl', 'backup', 'restore-check', 'cleanup-report'))
    parser.add_argument('--backup-path', type=Path)
    parser.add_argument('--environment', choices=('lab',), default='lab')
    parser.add_argument('--service', choices=SERVICES)
    parser.add_argument('--tail', type=int, default=100)
    parser.add_argument('--follow', action='store_true')
    args = parser.parse_args(argv)
    if (args.action == 'restore-check') != (args.backup_path is not None):
        parser.error('restore-check requires --backup-path, which is exclusive to restore-check')
    if args.action == 'logs' and (not args.service or args.tail < 0):
        parser.error('logs requires --service and a nonnegative --tail')
    if args.action != 'logs' and (args.service or args.follow):
        parser.error('--service and --follow are only supported for logs')
    if args.action in ('smoke', 'tls-check', 'renew-crl', 'cleanup-report'):
        import maintenance
        return {'smoke': maintenance.smoke, 'tls-check': maintenance.tls_check,
                'renew-crl': maintenance.renew_crl, 'cleanup-report': maintenance.cleanup_report}[args.action]()
    if args.action == 'backup':
        import backup
        backup.main()
        return 0
    if args.action == 'restore-check':
        import restore_check
        restore_check.main([str(args.backup_path)])
        return 0
    if args.action == 'config-check':
        check_configuration(collect())
        print('Lab configuration valid: 10 services, existing external volumes/networks, pinned current images.')
        return 0
    rows = collect()
    if args.action == 'inventory':
        print(json.dumps(summarize(rows), indent=2, ensure_ascii=False))
    elif args.action == 'status':
        print(f'Environment: lab | Project: {PROJECT}')
        for service, info in rows.items():
            health = info['State'].get('Health', {}).get('Status', '-')
            if not info['State'].get('Running'):
                health = '- (stopped)'
            print(f'{service:14} {info["State"]["Status"]:12} {health}')
    elif args.action in ('doctor', 'start'):
        report = diagnose(rows)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        if report['errors']:
            return 1
        if args.action == 'start':
            check_configuration(rows)
            sys.argv = [str(ROOT / 'scripts' / 'legacy' / 'operate.py'), 'start']
            legacy.main()
    elif args.action == 'stop':
        sys.argv = [str(ROOT / 'scripts' / 'legacy' / 'operate.py'), 'stop']
        legacy.main()
    else:
        command = ['docker', 'logs', '--tail', str(args.tail)]
        if args.follow:
            command.append('--follow')
        command.append(rows[args.service]['Id'])
        return subprocess.call(command)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        sys.exit(1)
