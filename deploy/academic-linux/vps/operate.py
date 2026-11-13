"""VPS-only ingress adapter. Base RC source and release locks remain immutable.

Seal this adapter separately against a production RC lock/config. Publication needs
an owner decision receipt; sealing itself is not approval. Never runs Cloud commands.
"""
import argparse
from contextlib import contextmanager
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent/'rc'))
import rc
from prepare import hosts

FILES = ('operate.py', 'prepare.py', 'compose.public.yaml')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def identity(config, manifest):
    return {'rc_lock_sha256': digest(manifest), 'config_sha256': digest(config),
            'adapter_hashes': {n: digest(HERE/n) for n in FILES}}


def validate_target(c):
    rc.check(c['mode'] == 'production-demo' and c['external_port'] == 443,
             'VPS adapter requires production-demo on 443')
    portal = c['portal_host']
    rc.check(portal.startswith('portal.') and portal.endswith('.sslip.io'), 'sslip.io hostname required')
    rc.check(hosts(portal[len('portal.'):-len('.sslip.io')]) == (portal, c['auth_host']),
             'Portal/Auth must refer to the same public IPv4')


def approval(path, seal):
    d = json.loads(path.read_text())
    rc.check(d.get('vps_lock_sha256') == digest(seal), 'Approval is for a different VPS lock')
    rc.check(all(d.get(k) == 'APPROVED' for k in ('D-04', 'D-14', 'D-17', 'G8')),
             'D-04/D-14/D-17/G8 approval required; never fabricate this receipt')
    rc.check(bool(d.get('owner')) and bool(d.get('decision_reference')), 'Owner decision reference required')
    expiry = dt.datetime.fromisoformat(d['expires_at'])
    rc.check(expiry.tzinfo is not None and expiry > dt.datetime.now(dt.timezone.utc), 'Approval expired')


def checked_public_model(original, effective):
    expected = json.loads(json.dumps(original))
    ports = expected['services']['ingress']['ports']
    rc.check(len(ports) == 1 and ports[0]['host_ip'] == '127.0.0.1', 'Expected loopback RC origin')
    public = dict(ports[0], host_ip='0.0.0.0', published='443')
    ports.append(public)
    rc.check(effective == expected, 'Public overlay changed more than the ingress port')


def context(args):
    rc.check(os.name == 'posix' and sys.platform.startswith('linux'), 'Runtime operations require Linux VPS')
    c, m, cmd, env = rc.configure(args.config, args.manifest, args.project, allow_production=True)
    validate_target(c)
    seal = json.loads(args.seal.read_text())
    rc.check(seal == identity(args.config, args.manifest), 'VPS adapter/config/RC lock drift')
    rc.check((c['state']/'installed').read_text() == digest(args.manifest), 'Installed RC lock mismatch')
    public_cmd = cmd + ['-f', str(HERE/'compose.public.yaml')]
    original = json.loads(rc.base.compose('--profile', '*', 'config', '--format', 'json').stdout)
    effective = json.loads(rc.run(*public_cmd, '--profile', '*', 'config', '--format', 'json', env=env).stdout)
    checked_public_model(original, effective)
    return c, m, cmd, public_cmd, env


@contextmanager
def exclusive(state):
    import fcntl
    with (state/'.vps-operation.lock').open('a') as f:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def write_private(path, data):
    rc.check(path.resolve() == path, 'Symlink destination rejected')
    fd, name = tempfile.mkstemp(prefix='.tls-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(name, 0o600)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def volume_tls(project, m, values):
    # Writes only three ingress TLS files, as ingress UID, no capabilities/network.
    name = project+'_ingress-config'
    owner = rc.run('docker', 'volume', 'inspect', '--format',
                   '{{index .Labels "com.docker.compose.project"}}', name).stdout.strip()
    rc.check(owner == project, 'Foreign ingress volume')
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as tar:
        for name, value in zip(('server.crt', 'server.key', 'edge-ca.crt'), values):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.uid, info.gid = len(value), 0o600, 101, 101
            tar.addfile(info, io.BytesIO(value))
    image = next(ref for ref in m['registry'] if ref.startswith('redis@'))
    result = subprocess.run(['docker', 'run', '--rm', '-i', '--pull', 'never', '--network', 'none', '--read-only',
                             '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--user', '101:101',
                             '--mount', f'type=volume,source={project}_ingress-config,target=/out',
                             '--entrypoint', 'tar', image, '-xf', '-', '-C', '/out'],
                            input=stream.getvalue(), capture_output=True, timeout=60)
    rc.check(result.returncode == 0, 'Ingress TLS volume update failed')


def destinations(c):
    # CA bundle is read-only system trust: never overwrite /etc/ssl/certs.
    return [Path(c['certificate']), Path(c['private_key']),
            *(c['state']/'ingress'/n for n in ('server.crt', 'server.key', 'edge-ca.crt'))]


def require_running_public(meta, project):
    rc.check(meta['Config']['Labels'].get('com.docker.compose.project') == project
             and meta['Config']['Labels'].get('com.docker.compose.service') == 'ingress'
             and meta['State']['Running'], 'Renewal must not reopen a stopped ingress')
    rc.check({'HostIp': '0.0.0.0', 'HostPort': '443'} in
             (meta['NetworkSettings']['Ports'].get('8443/tcp') or []), 'Renewal requires an already published ingress')


def verify_served(c, values):
    expected = ssl.PEM_cert_to_DER_cert(values[0].decode().split('-----END CERTIFICATE-----')[0]
                                      +'-----END CERTIFICATE-----\n')
    ctx = ssl.create_default_context(cafile=c['edge_ca'])
    for host in (c['portal_host'], c['auth_host']):
        with socket.create_connection(('127.0.0.1', c['bind_port']), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                rc.check(tls.getpeercert(binary_form=True) == expected, 'Served certificate differs')


def rotate(c, candidate, install, start, stop, verify):
    """Journal first; ingress stays stopped on interruption or unrecoverable failure."""
    journal = c['state']/'.tls-rollback'
    rc.check(not journal.exists(), 'Pending TLS rollback: use recover-tls before another operation')
    paths = destinations(c)
    old = [p.read_bytes() for p in paths]
    rc.check(all(p.is_file() and p.resolve() == p for p in paths), 'TLS destinations must be regular files')
    rc.check(all(p.parent.stat().st_mode & 0o077 == 0 for p in paths[:2]), 'PKI directory must be private')
    journal.mkdir(mode=0o700)
    for i, data in enumerate(old):
        write_private(journal/str(i), data)
    write_private(journal/'ready', b'complete\n')
    stop()
    try:
        for path, data in zip(paths, (*candidate[:2], *candidate)):
            write_private(path, data)
        install(candidate)
        start()
        verify(candidate)
    except Exception:
        stop()
        # Preserve the journal even after successful rollback for explicit recovery/inspection.
        for path, data in zip(paths, old):
            write_private(path, data)
        install(tuple(old[2:]))
        raise RuntimeError('TLS update failed; old TLS restored, ingress stopped; run recover-tls') from None
    for p in journal.iterdir():
        p.unlink()
    journal.rmdir()


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('seal', 'publish', 'close', 'renew-tls', 'recover-tls'))
    p.add_argument('--config', required=True, type=Path)
    p.add_argument('--manifest', required=True, type=Path)
    p.add_argument('--seal', required=True, type=Path)
    p.add_argument('--project', default='zt-academic-prod')
    p.add_argument('--approval', type=Path)
    p.add_argument('--fullchain', type=Path)
    p.add_argument('--key', type=Path)
    a = p.parse_args()
    if a.action == 'seal':
        c = rc.linux.load_config(a.config)
        validate_target(c)
        rc.check(json.loads(a.manifest.read_text())['mode'] == 'production-demo', 'Production lock required')
        with a.seal.open('x') as f:
            json.dump(identity(a.config, a.manifest), f, indent=2)
        print('VPS adapter sealed. No approval or deployment performed.')
        return
    c, m, cmd, public_cmd, env = context(a)
    with exclusive(c['state']):
        def stop():
            rc.run(*cmd, 'stop', '--timeout', '15', 'ingress', env=env)

        def start():
            rc.run(*public_cmd, 'up', '-d', '--no-deps', '--wait', '--wait-timeout', '45', 'ingress', env=env)

        if a.action == 'close':
            stop()
            print('Ingress stopped. Revoke the Cloud firewall rule separately.')
            return
        journal = c['state']/'.tls-rollback'
        if a.action == 'recover-tls':
            rc.check((journal/'ready').is_file(), 'No complete rollback journal; inspect without starting ingress')
            stop()
            for i, path in enumerate(destinations(c)):
                write_private(path, (journal/str(i)).read_bytes())
            values = tuple((journal/str(i)).read_bytes() for i in (2, 3, 4))
            volume_tls(a.project, m, values)
            rc.linux.prepare(c, rc.linux.load_pki(c))
            for f in journal.iterdir():
                f.unlink()
            journal.rmdir()
            print('Previous TLS restored. Ingress remains stopped; publish only after reviewing failure.')
            return
        rc.check(a.approval is not None, 'Owner approval receipt required')
        approval(a.approval, a.seal)
        rc.check(not journal.exists(), 'Pending TLS journal: recover before publishing')
        rc.linux.prepare(c, rc.linux.load_pki(c))
        if a.action == 'publish':
            try:
                start()
                verify_served(c, rc.linux.load_pki(c))
            except Exception:
                stop()
                raise
            print('Ingress published on host 443; Cloud firewall/access acceptance remains separate.')
        else:
            rc.check(a.fullchain is not None and a.key is not None, 'Candidate fullchain/key required')
            meta = json.loads(rc.run('docker', 'inspect', a.project+'-ingress-1').stdout)[0]
            require_running_public(meta, a.project)
            # Snapshot Certbot symlinks to private regular files before verification.
            with tempfile.TemporaryDirectory(prefix='.tls-candidate-', dir=c['state']) as td:
                cert, key = Path(td)/'fullchain.pem', Path(td)/'key.pem'
                write_private(cert, a.fullchain.read_bytes())
                write_private(key, a.key.read_bytes())
                candidate = rc.linux.load_pki(dict(c, certificate=str(cert), private_key=str(key)))
                rotate(c, candidate, lambda v: volume_tls(a.project, m, v), start, stop,
                       lambda v: verify_served(c, v))
            print('TLS rotated and verified for both hostnames; release/VPS locks unchanged.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Never print subprocess output, PEM data or secret-bearing command arguments.
        raise SystemExit('VPS action stopped: '+(str(error) if isinstance(error, RuntimeError)
                                               else type(error).__name__)) from None
