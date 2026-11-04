"""Plan/apply a stopped lab's bind-mount relocation without starting any service.

No database export/import, image build/pull, volume removal or runtime cleanup.
Private evidence and rollback inputs remain outside tracked source.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import zt

ROOT = zt.ROOT
STATE = ROOT / '.local-legacy' / 'phase3-runtime'
DESTINATION = ROOT.parent / 'runtime' / 'lab'
ROLES = {s: ('public-ca' if s == 'crl' else s) for s in zt.REQUIRED_FILES}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, *, log=None):
    result = subprocess.run(command, capture_output=True)
    if log:
        log.write_bytes(result.stdout + result.stderr)
    if result.returncode:
        # Compose config and inspect can include secrets: never echo their output.
        raise RuntimeError(f'Command failed: {command[0]}; inspect private evidence if available')
    return result.stdout


def compose(files, env_file):
    command = ['docker', 'compose', '--project-directory', str(ROOT),
               '--project-name', zt.PROJECT, '--env-file', str(env_file)]
    for file in files:
        command += ['-f', str(file)]
    return command


def require_stopped(rows):
    if set(rows) != set(zt.SERVICES):
        raise RuntimeError('Expected exactly the ten lab services')
    for service, info in rows.items():
        zt.validate_identity(service, info)
        if info['State']['Running'] or info['State'].get('Paused'):
            raise RuntimeError(f'{service}: stop the lab before relocating runtime')
    errors = zt.diagnose(rows)['errors']
    if errors:
        raise RuntimeError('Runtime preflight failed: ' + '; '.join(errors))


def source_root(rows):
    roots = set()
    for service, role in ROLES.items():
        target = '/public-ca' if service == 'crl' else '/run/demo'
        mounts = [m for m in rows[service]['Mounts'] if m['Type'] == 'bind']
        if len(mounts) != 1 or mounts[0]['Destination'] != target or mounts[0]['RW']:
            raise RuntimeError(f'{service}: unexpected bind mount layout')
        path = zt.host_path(mounts[0]['Source']).resolve()
        if path.name != role:
            raise RuntimeError(f'{service}: unexpected runtime role')
        roots.add(path.parent)
    if len(roots) != 1 or rows['frontend']['Mounts']:
        raise RuntimeError('Runtime roots are inconsistent')
    return roots.pop()


def runtime_files(source):
    # Include CA management and operator credentials, but not historical imports,
    # migration jobs or evidence. The old tree remains intact for rollback/history.
    selected = list(ROLES.values()) + ['authority', 'credentials.private.json', 'owner.json']
    files = {}
    for name in selected:
        path = source / name
        if not path.exists():
            if name in ROLES.values():
                raise RuntimeError(f'Missing role: {name}')
            continue
        entries = [path] if path.is_file() else sorted(path.rglob('*'))
        for entry in entries:
            if entry.is_symlink() or not entry.resolve().is_relative_to(source.resolve()):
                raise RuntimeError('Runtime contains a link outside its root')
            if entry.is_file():
                files[entry.relative_to(source).as_posix()] = digest(entry)
    return files


def contract(info):
    """Compare actual container settings; do not expose environment values."""
    config_keys = ('Entrypoint', 'Cmd', 'User', 'WorkingDir', 'Healthcheck', 'StopSignal',
                   'StopTimeout', 'ExposedPorts')
    host_keys = ('Memory', 'MemorySwap', 'MemoryReservation', 'NanoCpus', 'CpuShares',
                 'ReadonlyRootfs', 'CapDrop', 'CapAdd', 'SecurityOpt', 'Privileged',
                 'PortBindings', 'RestartPolicy', 'LogConfig', 'ExtraHosts', 'Tmpfs',
                 'PidsLimit', 'ShmSize', 'Ulimits', 'Dns', 'DnsSearch', 'Init')
    host = {k: info['HostConfig'].get(k) for k in host_keys}
    # Both null and [] mean no explicit DNS override, using Docker's defaults.
    for key in ('Dns', 'DnsSearch'):
        host[key] = host[key] or []
    return {'image_id': info['Image'],
            'config': {k: info['Config'].get(k) for k in config_keys},
            'environment': sorted(info['Config'].get('Env') or []),
            'host': host,
            'networks': sorted(info['NetworkSettings']['Networks']),
            'mounts': sorted((m['Type'], m.get('Name', ''), m['Destination'], m['RW'])
                             for m in info['Mounts'])}


def validate_model(model, rows, *, runtime_root=None):
    if set(model['services']) != set(zt.SERVICES):
        raise RuntimeError('Compose must contain only the ten lab services')
    if set(model['volumes']) != set(zt.DATA_VOLUMES.values()) or set(model['networks']) != {'core', 'edge'}:
        raise RuntimeError('Expected exactly four data volumes and two lab networks')
    for name, volume in model['volumes'].items():
        if not volume.get('external') or volume['name'] != f'{zt.PROJECT}_{name}':
            raise RuntimeError('Lab volumes must reference the existing external resources')
        zt.docker_json('volume', 'inspect', volume['name'])
    for name, network in model['networks'].items():
        if not network.get('external') or network['name'] != f'{zt.PROJECT}_{name}':
            raise RuntimeError('Lab networks must be external existing resources')
        actual = zt.docker_json('network', 'inspect', network['name'])[0]
        if bool(actual['Internal']) != (name == 'core'):
            raise RuntimeError(f'{name}: unexpected network isolation')
    for name, service in model['services'].items():
        info = rows[name]
        if 'build' in service or 'profiles' in service:
            raise RuntimeError('Lab runtime must not include builds or migration profiles')
        if service['image'] != info['Image'] or service['container_name'] != f'{zt.PROJECT}-{name}':
            raise RuntimeError(f'{name}: image or name differs from inspected container')
        bindings = [m for m in service.get('volumes', []) if m['type'] == 'bind']
        actual_bindings = [m for m in info['Mounts'] if m['Type'] == 'bind']
        if len(bindings) != len(actual_bindings):
            raise RuntimeError(f'{name}: bind mount count differs')
        for mount in bindings:
            actual = next((m for m in actual_bindings if m['Destination'] == mount['target']), None)
            if actual is None or bool(mount.get('read_only')) != (not actual['RW']):
                raise RuntimeError(f'{name}: bind mount target or access differs')
            expected = Path(runtime_root) / ROLES[name] if runtime_root is not None else zt.host_path(actual['Source'])
            if zt.host_path(mount['source']).resolve() != expected.resolve():
                raise RuntimeError(f'{name}: bind mount source differs')
        expected_volumes = {(m['Destination'], m['Name']) for m in info['Mounts'] if m['Type'] == 'volume'}
        declared_volumes = {(m['target'], model['volumes'][m['source']]['name'])
                            for m in service.get('volumes', []) if m['type'] == 'volume'}
        if declared_volumes != expected_volumes:
            raise RuntimeError(f'{name}: data volume mapping differs')
        image = zt.docker_json('image', 'inspect', info['Image'])[0]['Config']
        expected_env = dict(v.split('=', 1) for v in image.get('Env') or [])
        expected_env.update({k: str(v) for k, v in service.get('environment', {}).items()})
        actual_env = dict(v.split('=', 1) for v in info['Config'].get('Env') or [])
        if expected_env != actual_env:
            raise RuntimeError(f'{name}: environment drift; values withheld')
        for field, key in (('entrypoint', 'Entrypoint'), ('command', 'Cmd'),
                           ('user', 'User'), ('working_dir', 'WorkingDir')):
            expected = service.get(field)
            if expected is None:
                expected = image.get(key)
            if field in ('user', 'working_dir'):
                expected = expected or ''
            if expected != info['Config'].get(key):
                raise RuntimeError(f'{name}: {field} drift')
        memory = int(service.get('mem_limit', 0))
        if memory != info['HostConfig']['Memory']:
            raise RuntimeError(f'{name}: memory drift')
        if int(service.get('memswap_limit', memory * 2)) != info['HostConfig']['MemorySwap']:
            raise RuntimeError(f'{name}: swap limit drift')


def prepare():
    if (STATE / 'plan.private.json').exists():
        raise RuntimeError('Plan already exists; review it instead of replacing rollback evidence')
    rows = zt.collect()
    require_stopped(rows)
    source = source_root(rows)
    if DESTINATION.exists() or DESTINATION.resolve().is_relative_to(ROOT.resolve()):
        raise RuntimeError('Destination must be a new directory outside the source repository')
    files = runtime_files(source)
    if not STATE.exists():
        secure_directory(STATE)
    lock = {'services': {name: {'image': info['Image']} for name, info in rows.items()}}
    write_json(STATE / 'images.private.yaml', lock)
    (STATE / 'source.private.env').write_text(f'ZT_LAB_RUNTIME={source.as_posix()}\n', encoding='utf-8')
    prefix = compose([ROOT / 'compose.lab.yaml', STATE / 'images.private.yaml'], STATE / 'source.private.env')
    model = json.loads(run(prefix + ['config', '--format', 'json']))
    validate_model(model, rows)
    # A complete, resolved rollback model contains secrets. Keep it ignored/private.
    write_json(STATE / 'rollback.private.yaml', model)
    write_json(STATE / 'before.private.json', rows)
    plan = {'schema': 1, 'project': zt.PROJECT, 'source': str(source),
            'destination': str(DESTINATION), 'files': files,
            'compose_sha256': digest(ROOT / 'compose.lab.yaml'),
            'images_sha256': digest(STATE / 'images.private.yaml'),
            'containers': {s: i['Id'] for s, i in rows.items()},
            'status': 'prepared'}
    write_json(STATE / 'plan.private.json', plan)
    print(json.dumps({'status': 'prepared', 'source': str(source), 'destination': str(DESTINATION),
                      'files': len(files), 'services': len(rows), 'data_volumes': 4,
                      'action': 'copy runtime and recreate stopped containers with identical images'}, indent=2))


def secure_directory(path):
    path.mkdir(parents=True, exist_ok=False)
    if os.name == 'nt':
        # New private tree only. Use SID so Windows language does not affect ACL names.
        sid = run(['powershell', '-NoProfile', '-Command',
                   '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value']).decode().strip()
        run(['icacls', str(path), '/inheritance:r', '/grant:r',
             f'*{sid}:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F'])
    else:
        path.chmod(0o700)


def check_plan(plan, rows):
    require_stopped(rows)
    if {s: i['Id'] for s, i in rows.items()} != plan['containers']:
        raise RuntimeError('Container identity changed since preparation')
    if digest(ROOT / 'compose.lab.yaml') != plan['compose_sha256'] or digest(STATE / 'images.private.yaml') != plan['images_sha256']:
        raise RuntimeError('Compose inputs changed after review')
    if runtime_files(Path(plan['source'])) != plan['files']:
        raise RuntimeError('Private runtime changed after review')
    before = read_json(STATE / 'before.private.json')
    if any(contract(rows[s]) != contract(before[s]) for s in rows):
        raise RuntimeError('Container configuration changed after review')


def verify(plan):
    rows = zt.collect()
    require_stopped(rows)
    before = read_json(STATE / 'before.private.json')
    mismatches = [s for s in rows if contract(rows[s]) != contract(before[s])]
    if mismatches:
        raise RuntimeError('Container settings drift: ' + ', '.join(mismatches))
    if source_root(rows) != Path(plan['destination']).resolve():
        raise RuntimeError('Runtime mounts do not point to the new root')
    if runtime_files(Path(plan['destination'])) != plan['files']:
        raise RuntimeError('Copied runtime file hashes differ')
    write_json(STATE / 'after.private.json', rows)
    write_json(STATE / 'verification.json', {'status': 'passed', 'services': len(rows),
               'files_identical': len(plan['files']), 'images_unchanged': True,
               'container_settings_unchanged': True, 'volumes_unchanged': True,
               'services_started': 0, 'runtime': plan['destination']})
    print('PASS: 10 stopped containers, identical images/settings, 4 existing data volumes, runtime hashes match.')


def apply():
    plan = read_json(STATE / 'plan.private.json')
    if plan['status'] != 'prepared' or Path(plan['destination']).resolve() != DESTINATION.resolve():
        raise RuntimeError('Plan is not applicable to this destination')
    rows = zt.collect()
    check_plan(plan, rows)
    source, destination = Path(plan['source']), Path(plan['destination'])
    secure_directory(destination)
    for relative in plan['files']:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, target)
    if runtime_files(destination) != plan['files']:
        raise RuntimeError('Copy verification failed; no container changed')
    (destination / 'compose.private.env').write_text(
        f'COMPOSE_PROJECT_NAME={zt.PROJECT}\nCOMPOSE_PARALLEL_LIMIT=1\nZT_LAB_RUNTIME={destination.as_posix()}\n', encoding='utf-8')
    shutil.copy2(STATE / 'images.private.yaml', destination / 'images.private.yaml')
    prefix = compose([ROOT / 'compose.lab.yaml', destination / 'images.private.yaml'], destination / 'compose.private.env')
    model = json.loads(run(prefix + ['config', '--format', 'json']))
    validate_model(model, rows, runtime_root=destination)
    check_plan(plan, zt.collect())
    plan['status'] = 'applying'
    write_json(STATE / 'plan.private.json', plan)
    run(prefix + ['create', '--no-build', '--pull', 'never', *zt.SERVICES], log=STATE / 'create.private.log')
    verify(plan)
    plan['status'] = 'applied'
    write_json(STATE / 'plan.private.json', plan)


def rollback():
    plan = read_json(STATE / 'plan.private.json')
    require_stopped(zt.collect())
    if runtime_files(Path(plan['source'])) != plan['files']:
        raise RuntimeError('Original runtime changed; review before rollback')
    # $$ escapes resolved literals back through Compose interpolation.
    rollback_model = read_json(STATE / 'rollback.private.yaml')
    escaped = json.dumps(rollback_model).replace('$', '$$')
    (STATE / 'rollback-escaped.private.yaml').write_text(escaped, encoding='utf-8')
    prefix = compose([STATE / 'rollback-escaped.private.yaml'], STATE / 'source.private.env')
    run(prefix + ['create', '--no-build', '--pull', 'never', *zt.SERVICES], log=STATE / 'rollback.private.log')
    rows = zt.collect()
    require_stopped(rows)
    before = read_json(STATE / 'before.private.json')
    if source_root(rows) != Path(plan['source']).resolve() or any(contract(rows[s]) != contract(before[s]) for s in rows):
        raise RuntimeError('Rollback requires manual review')
    plan['status'] = 'rolled_back'
    write_json(STATE / 'plan.private.json', plan)
    print('Rollback verified; original runtime restored, services remain stopped.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'apply', 'verify', 'rollback'))
    action = parser.parse_args().action
    if action == 'verify':
        plan = read_json(STATE / 'plan.private.json')
        verify(plan)
        if plan['status'] == 'applying':
            plan['status'] = 'applied'
            write_json(STATE / 'plan.private.json', plan)
    else:
        globals()[action]()


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        sys.exit(1)
