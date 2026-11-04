"""Start/status/stop the existing candidate only. Never create, import or remove resources."""
import argparse
import json
import subprocess
import time

PROJECT = 'zerotrust-legacy-integration-20261026'
ORDER = ['school', 'risk-db', 'keycloak-db', 'redis', 'keycloak', 'crl',
         'frontend', 'risk', 'backend', 'gateway']


def docker(*args):
    result = subprocess.run(['docker', *args], capture_output=True, timeout=50)
    if result.returncode:
        stderr = result.stderr.decode(errors='replace').lower()
        if args[0] == 'start' and any(marker in stderr for marker in
                                      ('port is already allocated', 'ports are not available', 'address already in use')):
            raise RuntimeError('Host port conflict. Identify the listener on 28443, 28444 or 28445, then retry.')
        raise RuntimeError('Docker operation failed; inspect the exact candidate resource')
    return result.stdout


def inspect(service):
    info = json.loads(docker('inspect', PROJECT + '-' + service))[0]
    assert info['Config']['Labels'].get('app.owner') == PROJECT, 'RESOURCE_OWNERSHIP_MISMATCH'
    return info


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['start', 'status', 'stop'], default='status', nargs='?')
    args = parser.parse_args()
    # Verify all destinations before the first action; never create missing containers.
    expected = {service: inspect(service)['Id'] for service in ORDER}
    order = list(reversed(ORDER)) if args.action == 'stop' else ORDER
    for service in order:
        info = inspect(service)
        assert info['Id'] == expected[service], 'RESOURCE_IDENTITY_DRIFT'
        if args.action == 'stop' and info['State']['Running']:
            docker('stop', '--timeout', '35', info['Id'])
        if args.action == 'start':
            if not info['State']['Running']:
                docker('start', info['Id'])
            deadline = time.monotonic() + 150
            while time.monotonic() < deadline:
                info = inspect(service)
                if info['Id'] != expected[service] or not info['State']['Running']:
                    raise RuntimeError(f'{service}: exited or was replaced; run zt.cmd status and logs --service {service}')
                if info['State'].get('Health', {}).get('Status') == 'healthy':
                    break
                time.sleep(2)
            else:
                raise RuntimeError(f'{service}: health timeout; run zt.cmd logs --service {service} and zt.cmd doctor')
    states = {s: {'status': (i := inspect(s))['State']['Status'],
                  'health': i['State'].get('Health', {}).get('Status', 'NOT_CONFIGURED')}
              for s in ORDER}
    print(json.dumps({'project': PROJECT, 'services': states,
                      'Portal': 'https://localhost:28443', 'Keycloak': 'https://localhost:28444',
                      'Windows_Root_changes': 0}, indent=2))


if __name__ == '__main__':
    main()
