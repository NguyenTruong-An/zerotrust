"""Targeted offline boundary and TLS transaction tests; no existing Docker state used."""
import copy
import datetime as dt
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import operate as op
import prepare

# TEST ONLY: no network connections, DNS queries, or deployment output for this address.
TEST_IP = '8.8.8.8'


class VpsTests(unittest.TestCase):
    def test_missing_private_documentation_and_injected_ips_rejected(self):
        for ip in ('', '${STATIC_EXTERNAL_IP}', '127.0.0.1', '10.1.1.1', '203.0.113.1',
                   '169.254.169.254', '224.0.0.1', '::1', '1.2.3.4;return 200;'):
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                prepare.configuration(ip)

    def test_origin_configuration_and_cross_ip_denial(self):
        c = prepare.configuration(TEST_IP)
        op.validate_target(c)
        self.assertEqual(c['external_port'], 443)
        self.assertEqual(c['bind_port'], 34443)
        c['auth_host'] = 'auth.1.1.1.1.sslip.io'
        with self.assertRaises(RuntimeError):
            op.validate_target(c)

    def test_no_http_application_route_or_redirect_before_go(self):
        nginx = prepare.acme_nginx(TEST_IP)
        self.assertNotIn('proxy_pass', nginx)
        self.assertNotIn('return 30', nginx)
        self.assertIn('location / { return 404; }', nginx)
        self.assertIn('limit_except GET { deny all; }', nginx)
        self.assertIn('try_files $uri =404;', nginx)

    def test_only_ingress_port_may_change(self):
        original = {'services': {'ingress': {'ports': [dict(host_ip='127.0.0.1', published='34443', target=8443, protocol='tcp', mode='ingress')]},
                                 'mysql': {'networks': ['core']}}, 'networks': {'core': {'internal': True}}}
        public = copy.deepcopy(original)
        public['services']['ingress']['ports'].append(dict(original['services']['ingress']['ports'][0], host_ip='0.0.0.0', published='443'))
        op.checked_public_model(original, public)
        for mutate in ('db_port', 'network', 'tls', 'all_interfaces_origin'):
            bad = copy.deepcopy(public)
            if mutate == 'db_port': bad['services']['mysql']['ports'] = ['3306:3306']
            if mutate == 'network': bad['networks']['core']['internal'] = False
            if mutate == 'tls': bad['services']['ingress']['volumes'] = ['/tmp/key:/key']
            if mutate == 'all_interfaces_origin': bad['services']['ingress']['ports'][0]['host_ip'] = '0.0.0.0'
            with self.subTest(mutate=mutate), self.assertRaises(RuntimeError):
                op.checked_public_model(original, bad)

    def test_approval_is_exact_expiring_and_requires_all_gates(self):
        with tempfile.TemporaryDirectory() as td:
            seal, receipt = Path(td)/'seal', Path(td)/'approval'
            seal.write_text('test seal')
            good = {k: 'APPROVED' for k in ('D-04', 'D-14', 'D-17', 'G8')}
            good.update(vps_lock_sha256=op.digest(seal), owner='TEST ONLY', decision_reference='TEST ONLY',
                        expires_at=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1)).isoformat())
            receipt.write_text(json.dumps(good))
            op.approval(receipt, seal)
            for key, value in [('G8', 'PENDING'), ('D-14', 'PENDING'), ('D-17', 'PENDING'),
                               ('D-04', 'PENDING'), ('vps_lock_sha256', 'wrong'),
                               ('expires_at', '2000-01-01T00:00:00+00:00')]:
                receipt.write_text(json.dumps(dict(good, **{key: value})))
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    op.approval(receipt, seal)

    def test_renewal_never_reopens_closed_or_foreign_ingress(self):
        m = dict(Config={'Labels': {'com.docker.compose.project': 'zt-academic-prod',
                                    'com.docker.compose.service': 'ingress'}}, State={'Running': True},
                 NetworkSettings={'Ports': {'8443/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '443'}]}})
        op.require_running_public(m, 'zt-academic-prod')
        for change in ('stopped', 'loopback', 'foreign'):
            bad = copy.deepcopy(m)
            if change == 'stopped': bad['State']['Running'] = False
            if change == 'loopback': bad['NetworkSettings']['Ports']['8443/tcp'] = []
            if change == 'foreign': bad['Config']['Labels']['com.docker.compose.project'] = 'zt-academic-demo'
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                op.require_running_public(bad, 'zt-academic-prod')

    def transaction_fixture(self, directory):
        p = Path(directory)
        state, pki = p/'state', p/'pki'
        state.mkdir(mode=0o700)
        (state/'ingress').mkdir(mode=0o700)
        pki.mkdir(mode=0o700)
        c = dict(state=state, certificate=str(pki/'fullchain.pem'), private_key=str(pki/'key.pem'))
        for i, path in enumerate(op.destinations(c)):
            op.write_private(path, f'old-{i}'.encode())
        return c

    @unittest.skipUnless(os.name == 'posix', 'POSIX permissions required')
    def test_tls_success_updates_both_locations_without_lock_change(self):
        with tempfile.TemporaryDirectory() as td:
            c = self.transaction_fixture(td)
            lock = Path(td)/'release-lock.json'
            lock.write_text('immutable')
            before = op.digest(lock)
            calls = []
            op.rotate(c, (b'cert', b'key', b'ca'), lambda v: calls.append(('install', v)),
                      lambda: calls.append('start'), lambda: calls.append('stop'), lambda v: calls.append('verified'))
            self.assertEqual([p.read_bytes() for p in op.destinations(c)], [b'cert', b'key', b'cert', b'key', b'ca'])
            self.assertEqual(calls[0], 'stop')
            self.assertFalse((c['state']/'.tls-rollback').exists())
            self.assertEqual(op.digest(lock), before)

    @unittest.skipUnless(os.name == 'posix', 'POSIX permissions required')
    def test_tls_failure_restores_and_leaves_ingress_stopped(self):
        for phase in ('install', 'start', 'verify'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as td:
                c = self.transaction_fixture(td)
                old = [p.read_bytes() for p in op.destinations(c)]
                calls = []
                def install(v):
                    calls.append('install')
                    if phase == 'install' and v[0] == b'new': raise RuntimeError('test')
                def start():
                    calls.append('start')
                    if phase == 'start': raise RuntimeError('test')
                def verify(v): raise RuntimeError('test')
                with self.assertRaises(RuntimeError):
                    op.rotate(c, (b'new', b'key', b'ca'), install, start, lambda: calls.append('stop'), verify)
                self.assertEqual([p.read_bytes() for p in op.destinations(c)], old)
                self.assertEqual(calls[-2:], ['stop', 'install'])
                self.assertTrue((c['state']/'.tls-rollback/ready').exists())
                with self.assertRaises(RuntimeError):
                    op.rotate(c, (b'new', b'key', b'ca'), install, start, lambda: None, verify)

    @unittest.skipUnless(os.name == 'posix', 'OpenSSL/POSIX required')
    def test_candidate_key_san_chain_and_expiry_checked(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            now = dt.datetime.now(dt.timezone.utc)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'TEST ONLY')])
            ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
                  .serial_number(1).not_valid_before(now-dt.timedelta(days=1)).not_valid_after(now+dt.timedelta(days=2))
                  .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(ca_key, hashes.SHA256()))
            portal, auth = prepare.hosts(TEST_IP)
            def cert(names, expired=False):
                leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, portal)])
                return (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(name).public_key(key.public_key())
                        .serial_number(2).not_valid_before(now-dt.timedelta(days=2))
                        .not_valid_after(now+dt.timedelta(days=-1 if expired else 1))
                        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), False)
                        .sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
            def pem(k): return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            op.write_private(p/'key', pem(key))
            op.write_private(p/'ca', ca.public_bytes(serialization.Encoding.PEM))
            c = dict(mode='production-demo', certificate=str(p/'cert'), private_key=str(p/'key'), edge_ca=str(p/'ca'),
                     portal_host=portal, auth_host=auth)
            for names, expired, success in [([portal, auth], False, True), ([portal], False, False), ([portal, auth], True, False)]:
                op.write_private(p/'cert', cert(names, expired))
                if success: self.assertEqual(len(op.rc.linux.load_pki(c)), 3)
                else:
                    with self.assertRaises(RuntimeError): op.rc.linux.load_pki(c)
            op.write_private(p/'cert', cert([portal, auth]))
            op.write_private(p/'key', pem(ca_key))
            with self.assertRaises(RuntimeError): op.rc.linux.load_pki(c)
            op.write_private(p/'key', pem(key))
            op.write_private(p/'ca', cert([portal, auth]))
            with self.assertRaises(RuntimeError): op.rc.linux.load_pki(c)


if __name__ == '__main__':
    unittest.main()
