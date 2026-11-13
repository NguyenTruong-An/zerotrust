"""Opt-in targeted Compose/NGINX checks. No published ports or existing volumes.

Requires the already-present pinned NGINX image; never pulls an image.
"""
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import unittest

import operate as op
import prepare

TEST_IP = '8.8.8.8'  # Fixture only: never connect to this address.


@unittest.skipUnless(os.getenv('VPS_NATIVE_CHECKS') == '1', 'Explicit isolated native checks only')
class NativeChecks(unittest.TestCase):
    def test_compose_overlay_changes_only_public_ingress_port(self):
        root = op.rc.ROOT
        env = {k: v for k, v in os.environ.items() if not k.startswith(('COMPOSE_', 'AD_'))}
        env.update(ACADEMIC_STATE='/tmp/vps-offline-config-not-created', AD_BIND_PORT='34443',
                   AD_PORTAL_HOST=prepare.hosts(TEST_IP)[0], AD_EXTERNAL_PORT='443', AD_INGRESS_IP='172.31.243.9',
                   AD_CORE_SUBNET='172.31.243.0/27', AD_FRONTEND_IMAGE='offline/frontend:test',
                   AD_RC_PROJECT='zt-academic-prod', AD_RC_KC='offline/keycloak:test',
                   AD_RC_BACKEND='offline/backend:test', AD_RC_RISK='offline/risk:test', AD_RC_GATEWAY='offline/gateway:test')
        cmd = ['docker', 'compose', '-p', 'zt-academic-prod', '--project-directory', str(root/'deploy/academic-demo')]
        for file in ('deploy/academic-demo/compose.academic-demo.yaml', 'deploy/academic-linux/compose.production-demo.yaml',
                     'deploy/academic-linux/rc/compose.rc.yaml'):
            cmd += ['-f', str(root/file)]
        def model(args):
            return json.loads(subprocess.check_output(args+['--profile', '*', 'config', '--format', 'json'], env=env))
        original = model(cmd)
        effective = model(cmd+['-f', str(op.HERE/'compose.public.yaml')])
        op.checked_public_model(original, effective)

    def test_acme_nginx_native_allow_challenge_only(self):
        image = next(ref for ref in op.rc.REGISTRY if ref.startswith('nginx:'))
        conf = prepare.acme_nginx(TEST_IP).replace('/run/zerotrust-acme.pid', '/tmp/nginx.pid')
        conf = conf.replace('/var/www/zerotrust-acme', '/tmp/webroot')
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w') as tar:
            value = conf.encode()
            info = tarfile.TarInfo('acme.conf')
            info.size, info.mode = len(value), 0o600
            tar.addfile(info, io.BytesIO(value))
        script = '''set -eu
tar -xf - -C /tmp
mkdir -p /tmp/webroot/.well-known/acme-challenge
printf token > /tmp/webroot/.well-known/acme-challenge/test-token
nginx -t -c /tmp/acme.conf
nginx -c /tmp/acme.conf
trap 'nginx -s quit -c /tmp/acme.conf' EXIT
status() { curl --silent --output /dev/null --write-out '%{http_code}' "$@"; }
test "$(status -H 'Host: portal.8.8.8.8.sslip.io' http://127.0.0.1/.well-known/acme-challenge/test-token)" = 200
test "$(status -H 'Host: auth.8.8.8.8.sslip.io' http://127.0.0.1/.well-known/acme-challenge/test-token)" = 200
test "$(status -H 'Host: portal.8.8.8.8.sslip.io' http://127.0.0.1/)" = 404
test "$(status -H 'Host: auth.8.8.8.8.sslip.io' http://127.0.0.1/realms/academic-demo/)" = 404
test "$(status -H 'Host: attacker.invalid' http://127.0.0.1/.well-known/acme-challenge/test-token)" = 404
test "$(status -X PUT -H 'Host: portal.8.8.8.8.sslip.io' http://127.0.0.1/.well-known/acme-challenge/test-token)" = 403
test "$(status --path-as-is -H 'Host: portal.8.8.8.8.sslip.io' http://127.0.0.1/.well-known/acme-challenge/../../../etc/passwd)" = 400
'''
        r = subprocess.run(['docker', 'run', '--rm', '-i', '--pull', 'never', '--network', 'none',
                            '--entrypoint', 'sh', image, '-c', script], input=stream.getvalue(),
                           capture_output=True, timeout=45)
        self.assertEqual(r.returncode, 0, r.stderr.decode(errors='replace'))


if __name__ == '__main__':
    unittest.main()
