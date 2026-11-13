"""Bounded synthetic compatibility harness. Not a release installer or release lock."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE.parent/'rc'))
import rc

PROJECT = 'zt-security-20261110'
ENGINE_ID = 'e87199e0-3944-4e49-a66f-e1adc093d1ae'
STATE = Path('/tmp/zerotrust-security-20261110')
OUT = ROOT/'target/bounded-remediation-20261110'
RECEIPT = OUT/'candidate-images.json'
SUBNET = '10.253.241.0/27'
CANDIDATES = {k: f'zt-security-candidate/{k}:20261110-1' for k in ('keycloak', 'mysql84', 'mysql80')}


def configure():
    rc.check(sys.platform.startswith('linux'), 'Use isolated Linux state')
    rc.check(rc.run('docker', 'info', '--format', '{{.ID}}').stdout.strip() == ENGINE_ID,
             'Canonical Docker Engine ID mismatch')
    baseline = json.loads((ROOT/'target/pd-r27/release-lock.json').read_text())
    images = {k: v['image'] for k, v in baseline['builds'].items()}
    images['keycloak'] = CANDIDATES['keycloak']
    ids = {v: rc.image_id(v) for v in {*images.values(), *CANDIDATES.values()}}
    rc.check(all(ids.values()), 'Build all three candidate images first')
    for k in ('backend', 'risk', 'gateway', 'frontend'):
        rc.check(ids[images[k]] == baseline['builds'][k]['id'], 'Existing application image drift')
    receipt = {'kind': 'synthetic-candidate-only-NOT-A-RELEASE-LOCK', 'images': ids,
               'source': rc.run('git', 'rev-parse', 'HEAD').stdout.strip()}
    if RECEIPT.exists():
        rc.check(json.loads(RECEIPT.read_text()) == receipt, 'Candidate image changed during this run')
    else:
        RECEIPT.write_text(json.dumps(receipt, indent=2)+'\n')
    c = rc.linux.load_config(HERE.parent/'rc/rehearsal.json')
    network = ipaddress.ip_network(SUBNET)
    c.update(state=STATE, state_dir=str(STATE), core_subnet=SUBNET,
             network=network, proxy_ip=str(network.network_address + 9), frontend_image=images['frontend'])
    rc.linux.PROJECT = rc.linux.SCOPE = PROJECT
    rc.linux.activate(c)
    rc.base.VOLUMES.add('mysql-bootstrap-data')
    rc.base.EXACT_IMAGES = {ref: value.removeprefix('sha256:') for ref, value in ids.items()}
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith(('COMPOSE_', 'AD_'))}
    env.update(ACADEMIC_STATE=str(STATE), AD_BIND_PORT=str(c['bind_port']), AD_PORTAL_HOST=c['portal_host'],
               AD_EXTERNAL_PORT=str(c['external_port']), AD_INGRESS_IP=c['proxy_ip'], AD_CORE_SUBNET=SUBNET,
               AD_FRONTEND_IMAGE=images['frontend'], AD_RC_PROJECT=PROJECT, AD_RC_KC=images['keycloak'],
               AD_RC_BACKEND=images['backend'], AD_RC_RISK=images['risk'], AD_RC_GATEWAY=images['gateway'])
    cmd = ['docker', 'compose', '-p', PROJECT, '--project-directory', str(rc.linux.LOCAL)]
    for path in (rc.linux.LOCAL/'compose.academic-demo.yaml', HERE.parent/'compose.production-demo.yaml',
                 HERE.parent/'rc/compose.rc.yaml', HERE/'compose.candidate.yaml'):
        cmd.extend(['-f', str(path)])
    def compose(*args, check=True, data=None, timeout=420):
        p = subprocess.run([*cmd, *args], env=env, input=data, capture_output=True,
                           text=True, encoding='utf-8', timeout=timeout)
        if check and p.returncode:
            # No secret-bearing container log or SQL dump may reach the report.
            raise RuntimeError(f'Candidate Compose {args[0]} failed, exit={p.returncode}')
        return p
    rc.base.compose = compose
    rc.base.verify_boundary()
    model = json.loads(compose('--profile', '*', 'config', '--format', 'json').stdout)
    rc.check(all(s['labels'].get('io.zerotrust.scope') == PROJECT for s in model['services'].values()), 'Foreign scope')
    rc.check(model['networks']['core']['internal'] and model['networks']['recovery']['internal'], 'Private networks required')
    rc.check(all(not v.get('external') for v in model['volumes'].values()), 'External volume rejected')
    rc.check(all(not s.get('ports') for n, s in model['services'].items() if n != 'ingress'), 'Unexpected published port')
    rc.check(model['services']['mysql80']['image'] == CANDIDATES['mysql80']
             and model['services']['mysql']['image'] == CANDIDATES['mysql84'], 'Candidate engine drift')
    return c


def database_checks():
    rc.check(rc.sql('mysql', 'SELECT VERSION()') == '8.4.13', 'Runtime version changed')
    tls = rc.sql('mysql', "SHOW SESSION STATUS LIKE 'Ssl_cipher'", 'school')
    rc.check(bool(tls.split('\t')[-1]), 'School connection not TLS')
    grants = rc.sql('mysql', 'SHOW GRANTS FOR CURRENT_USER', 'school').splitlines()
    rc.check(len(grants) == 6 and sum('GRANT SELECT ON' in v for v in grants) == 5, 'School grants drift')
    denied = rc.base.compose('exec', '-T', 'mysql', 'mysql', '--defaults-extra-file=/fixture/school.cnf',
                             '-Nse', 'DELETE FROM scores WHERE 1=0', check=False)
    rc.check(denied.returncode != 0 and '1142' in denied.stderr, 'Write unexpectedly allowed')
    denied = rc.base.compose('exec', '-T', 'mysql', 'mysql', '--defaults-extra-file=/fixture/root.cnf',
                             '--password=deliberately-invalid-test-password', '-Nse', 'SELECT 1', check=False)
    rc.check(denied.returncode != 0 and '1045' in denied.stderr, 'Bad password accepted')
    denied = rc.base.compose('exec', '-T', 'mysql', 'mysql', '--defaults-extra-file=/fixture/school.cnf',
                             '--host=127.0.0.1', '-Nse', 'SELECT 1', check=False)
    rc.check(denied.returncode != 0 and ('2026' in denied.stderr or 'certificate' in denied.stderr.lower()),
             'Hostname-mismatched TLS connection accepted')
    print('PASS authentication, TLS hostname validation, School SELECT-only grants and write denial', flush=True)


def restore_check():
    # New recovery volume only. SQL is transferred in memory and never printed.
    expected_schema = rc.schema('mysql', 'pd_staging_')
    expected_ledger = rc.ledger('mysql', 'pd_staging_')
    schemas = ['pd_staging_school', 'pd_staging_risk', 'pd_staging_keycloak']
    dump = rc.base.compose('exec', '-T', 'mysql', 'mysqldump', '--defaults-extra-file=/fixture/root.cnf',
                           '--single-transaction', '--set-gtid-purged=OFF', '--no-tablespaces', '--hex-blob',
                           '--databases', *schemas).stdout
    rc.base.compose('up', '-d', '--wait', '--wait-timeout', '150', 'mysql-restore')
    try:
        rc.base.compose('exec', '-T', 'mysql-restore', 'mysql', '--defaults-extra-file=/fixture/root.cnf', data=dump)
        rc.check(rc.schema('mysql-restore', 'pd_staging_') == expected_schema, 'Restored Risk schema mismatch')
        rc.check(rc.ledger('mysql-restore', 'pd_staging_') == expected_ledger, 'Restored Flyway ledger mismatch')
        for table in ('pd_staging_school.scores', 'pd_staging_keycloak.REALM',
                      'pd_staging_keycloak.CREDENTIAL', 'pd_staging_risk.known_devices'):
            query = f'CHECKSUM TABLE {table} EXTENDED'
            source = rc.sql('mysql', query)
            rc.check(source.split('\t')[-1].isdigit() and rc.sql('mysql-restore', query) == source,
                     'Restored row checksum mismatch')
        rc.check(rc.sql('mysql-restore', rc.V5) == '661092940\t1', 'Restored V5 mismatch')
        print('PASS logical restore into new MySQL 8.4.13 candidate volume, schema/row checksums/V5', flush=True)
    finally:
        rc.base.compose('stop', '--timeout', '40', 'mysql-restore')


def risk_checks():
    from uuid import uuid4
    import risk_smoke as fixture

    code, _ = fixture.post(fixture.BASE+'/risk/evaluations', '{}')
    rc.check(code == 401, 'Risk accepted an unauthenticated caller')
    token = fixture.issue(fixture.CLIENT)
    low, high = str(uuid4()), str(uuid4())
    fixture.seed_history(token, low)
    fixture.seed_history(token, high, offset=2)
    challenge = fixture.evaluate(token, low, '198.51.100.22')
    fixture.assert_risk(challenge, 'MEDIUM', 'STEP_UP_MFA', 'Mandatory MFA')
    fixture.assert_risk(fixture.evaluate(token, low, '203.0.113.3'), 'MEDIUM', 'STEP_UP_MFA', 'numeric MEDIUM')
    status, _ = fixture.api('/trusted-devices', {'subjectId': low, 'deviceId': fixture.DEVICE,
                            'trustGeneration': challenge['trustGeneration']}, token)
    rc.check(status == 204, 'Synthetic trusted-device registration failed')
    fixture.assert_risk(fixture.evaluate(token, low, '198.51.100.22'), 'LOW', 'ALLOW', 'trusted LOW')
    for _ in range(5):
        status, _ = fixture.api('/authentication-failures', {'eventId': str(uuid4()),
                                'subjectId': high, 'sourceIp': '203.0.113.4'}, token)
        rc.check(status == 204, 'Synthetic Redis history write failed')
    before = fixture.evaluate(token, high, '203.0.113.4', None)
    fixture.assert_risk(before, 'HIGH', 'DENY', 'numeric HIGH via private API')
    rc.base.compose('restart', 'redis')
    rc.base.compose('up', '-d', '--wait', '--wait-timeout', '80', 'redis', 'risk')
    after = fixture.evaluate(token, high, '203.0.113.4', None)
    rc.check((after['decision'], after['riskScore']) == (before['decision'], before['riskScore']),
             'Redis history changed after restart')
    print('PASS unauthenticated Risk request denied and Redis AOF persistence', flush=True)


def mysql_persistence():
    queries = (rc.V5, 'SELECT COUNT(*) FROM pd_staging_school.scores',
               'SELECT COUNT(*) FROM pd_staging_keycloak.CREDENTIAL',
               'SELECT COUNT(*) FROM pd_staging_risk.known_devices')
    expected = [rc.sql('mysql', query) for query in queries]
    rc.base.compose('restart', 'mysql')
    rc.base.compose('up', '-d', '--wait', '--wait-timeout', '120', 'mysql')
    rc.check([rc.sql('mysql', query) for query in queries] == expected, 'MySQL records changed after restart')
    print('PASS MySQL named-volume persistence after restart', flush=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('action', choices=('install', 'risk', 'restore', 'stop'))
    a = p.parse_args()
    c = configure()
    if a.action == 'install':
        rc.bootstrap(c, PROJECT, RECEIPT)
        database_checks()
        rc.Smoke(c).infrastructure()
    elif a.action == 'risk':
        risk_checks()
    elif a.action == 'restore':
        rc.base.compose('stop', '--timeout', '45', 'ingress', 'gateway', 'frontend', 'backend', 'risk', 'keycloak')
        mysql_persistence()
        restore_check()
    else:
        rc.stop()
        rc.base.compose('stop', '--timeout', '40', 'mysql-restore')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('Candidate stopped: '+(str(error) if type(error) is RuntimeError else type(error).__name__)) from None
