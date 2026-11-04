"""Lab checks, staged CRL renewal and read-only cleanup inventory. Never delete resources."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import ssl
import subprocess
import urllib.request

import zt

RUNTIME = zt.ROOT.parent / 'runtime/lab'


def classify_image(identifier, tags, used, protected, definitions):
    if identifier in used:
        return 'in_use'
    if identifier in protected:
        return 'keep_release_or_rollback'
    if any('rollback' in tag.lower() for tag in tags) or any(tag in definitions for tag in tags) or identifier in definitions:
        return 'keep_config_reference_or_rollback'
    return 'review_unused'


def smoke():
    rows = zt.collect()
    failures = [s for s, i in rows.items() if not i['State']['Running'] or
                i['State'].get('Health', {}).get('Status') != 'healthy']
    context = ssl.create_default_context(cafile=str(RUNTIME / 'public-ca/ca.crt'))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context))
    checks = {}
    for name, url in {'portal': 'https://localhost:28443/',
                      'oidc': 'https://localhost:28444/realms/DoAn/.well-known/openid-configuration',
                      'crl': 'http://localhost:28445/ca.crl'}.items():
        try:
            with opener.open(url, timeout=20) as response:
                body = response.read()
                ok = response.status == 200 and bool(body)
                if name == 'oidc':
                    ok &= json.loads(body)['issuer'] == 'https://localhost:28444/realms/DoAn'
                if name == 'crl':
                    ok &= body == (RUNTIME / 'public-ca/ca.crl').read_bytes()
                checks[name] = 'passed' if ok else 'failed'
        except Exception as error:
            checks[name] = type(error).__name__
    for source, target, status in (
            ('gateway', 'https://backend:8443/api/students/me', '401'),
            ('gateway', 'https://keycloak:28444/realms/DoAn/.well-known/openid-configuration', '200'),
            ('backend', 'https://risk:8443/actuator/health', '200')):
        probe = subprocess.run(['docker', 'exec', rows[source]['Id'], 'java', '@/run/demo/jvm.args',
                                '-Dcom.sun.net.ssl.checkRevocation=true', '-Dcom.sun.security.enableCRLDP=true',
                                '-cp', '/app/tools', 'Health', target, status], capture_output=True, timeout=40)
        checks[f'{source}->{target.split("/")[2]}'] = 'passed' if probe.returncode == 0 else 'failed'
    result = {'timestamp': dt.datetime.now(dt.timezone.utc).isoformat(),
              'unhealthy_services': failures, 'checks': checks,
              'scope': 'Health, HTTPS trust/hostname, OIDC discovery and served CRL bytes; not login/MFA acceptance.'}
    print(json.dumps(result, indent=2))
    return int(bool(failures) or any(v != 'passed' for v in checks.values()))


def cleanup_report():
    ids = subprocess.check_output(['docker', 'ps', '-aq']).decode().split()
    containers = zt.docker_json('inspect', *ids) if ids else []
    used = {i['Image'] for i in containers}
    protected = set(used)
    for path in (RUNTIME / 'images.private.yaml',
                 zt.ROOT / '.local-legacy/phase3-runtime/images.private.yaml'):
        if path.exists():
            protected.update(v['image'] for v in json.loads(path.read_text())['services'].values())
    for path in (zt.ROOT / '.build-artifacts').glob('*/build-manifest.json'):
        protected.update(v['image_id'] for v in json.loads(path.read_text())['services'].values()
                         if v.get('status') == 'passed' and 'image_id' in v)
    for path in (zt.ROOT.parent / 'backups').glob('lab-*/manifest.json'):
        protected.update(json.loads(path.read_text(encoding='utf-8')).get('images', {}).values())
    rollout = zt.ROOT / '.local-legacy/risk-observation/verification/rollout.private.json'
    if rollout.is_file():
        old_image = json.loads(rollout.read_text(encoding='utf-8')).get('old_image')
        if old_image:
            protected.add(old_image)
    image_ids = sorted(set(subprocess.check_output(['docker', 'image', 'ls', '-aq', '--no-trunc']).decode().split()))
    images = zt.docker_json('image', 'inspect', *image_ids) if image_ids else []
    definitions = '\n'.join(p.read_text(encoding='utf-8') for p in
                            list(zt.ROOT.glob('compose*.yaml')) + list((zt.ROOT / 'deploy/docker').glob('Dockerfile.*')))
    inventory = []
    for i in images:
        identifier = i['Id']
        tags = i.get('RepoTags') or []
        role = classify_image(identifier, tags, used, protected, definitions)
        inventory.append({'id': identifier, 'tags': tags, 'size_bytes': i['Size'], 'classification': role})
    output = zt.ROOT / '.local-legacy/maintenance'
    output.mkdir(parents=True, exist_ok=True)
    report = {'timestamp': dt.datetime.now(dt.timezone.utc).isoformat(), 'images': inventory,
              'bind_sources': sorted({m['Source'] for c in containers for m in c['Mounts'] if m['Type'] == 'bind'}),
              'note': 'Unused is only a review candidate. Check Dockerfile base images, archived rollback manifests and all image aliases before deletion. Sizes share layers; not reclaim estimates.'}
    (output / 'cleanup-inventory.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({'report': str(output / 'cleanup-inventory.json'),
                      'counts': {k: sum(i['classification'] == k for i in inventory)
                                 for k in ('in_use', 'keep_release_or_rollback', 'keep_config_reference_or_rollback', 'review_unused')},
                      'resources_deleted': 0}, indent=2))
    return 0


def tls_check():
    image = zt.collect()['crl']['Image']
    script = zt.ROOT / 'deploy/legacy/tls_material.py'
    return subprocess.call(['docker', 'run', '--rm', '--network', 'none', '--read-only',
                            '--entrypoint', '/opt/tools/bin/python',
                            '--mount', f'type=bind,src={RUNTIME},dst=/state,readonly',
                            '--mount', f'type=bind,src={script},dst=/tls.py,readonly',
                            image, '/tls.py', '--state', '/state', '--check'])


def renew_crl():
    image = zt.collect()['crl']['Image']
    script = zt.ROOT / 'deploy/legacy/tls_material.py'
    evidence = zt.ROOT / '.local-legacy/maintenance'
    evidence.mkdir(parents=True, exist_ok=True)
    name = 'crl-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--read-only',
                    '--entrypoint', '/opt/tools/bin/python',
                    '--mount', f'type=bind,src={RUNTIME},dst=/state,readonly',
                    '--mount', f'type=bind,src={script},dst=/source/deploy/legacy/tls_material.py,readonly',
                    '--mount', f'type=bind,src={evidence},dst=/source/.local-legacy',
                    image, '/source/deploy/legacy/tls_material.py', '--state', '/state',
                    '--output', f'/source/.local-legacy/{name}'], check=True)
    staged = evidence / name
    manifest = json.loads((staged / 'manifest.json').read_text())
    for relative, expected in manifest['inputs_sha256'].items():
        if hashlib.sha256((RUNTIME / relative).read_bytes()).hexdigest() != expected:
            raise RuntimeError('TLS input changed after staging; no CRL installed')
    data = (staged / 'candidate/public-ca/ca.crl').read_bytes()
    if hashlib.sha256(data).hexdigest() != manifest['changes']['public-ca/ca.crl']['candidate']:
        raise RuntimeError('Candidate hash mismatch')
    target = RUNTIME / 'public-ca/ca.crl'
    temporary = target.with_suffix('.crl.new')
    temporary.write_bytes(data)
    temporary.replace(target)
    print('CRL renewed; previous copy retained in ' + str(staged / 'before'))
    return tls_check()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('smoke', 'cleanup-report', 'tls-check', 'renew-crl'))
    args = parser.parse_args()
    raise SystemExit({'smoke': smoke, 'cleanup-report': cleanup_report, 'tls-check': tls_check,
                     'renew-crl': renew_crl}[args.action]())
