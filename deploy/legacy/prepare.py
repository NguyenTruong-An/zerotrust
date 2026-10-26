"""Prepare private configuration only. No database clients, Docker calls or synthetic fixtures."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess

PROJECT = 'zerotrust-legacy-integration-20261026'
ISSUER = 'https://localhost:28444/realms/DoAn'
ORIGIN = 'https://localhost:28443'


def prepare(source, state):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    state.mkdir(parents=True, exist_ok=True)
    marker = state / 'owner.json'
    if marker.exists():
        assert json.loads(marker.read_text())['owner'] == PROJECT
        print('Existing private legacy configuration retained. No seed or reset.'); return
    assert not (state / 'credentials.private.json').exists(), 'PARTIAL_PREPARATION_REVIEW_REQUIRED'
    def save(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2) if isinstance(value, (dict, list)) else value)
        path.chmod(0o600)
    def props(role, values):
        def escape(v):
            return str(v).replace('\\', '\\\\').replace('\n', '\\n').replace('\r', '\\r')
        save(state / role / 'application.properties', ''.join(k + '=' + escape(v) + '\n' for k, v in values.items()))
    env = {}
    for line in (source / 'configuration/.env.private').read_text(encoding='utf-8-sig').splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            k, v = line.split('=', 1); env[k.strip()] = v.strip().strip('"\'')
    for key in ['RISK_DEVICE_FINGERPRINT_PEPPER', 'RISK_AUTH_HISTORY_PEPPER', 'RISK_DB_PASSWORD']:
        assert env.get(key), 'MISSING_ORIGINAL_LEGACY_SECRET_' + key
    realm_dir = source / 'backups/keycloak-realm-export-private'
    realm = json.loads((realm_dir / 'DoAn-realm.json').read_text(encoding='utf-8'))
    verified=json.loads((source/'execution/keycloak-export-summary.json').read_text())['DoAn']
    assert realm['id']==verified['realm_id'] and len(realm['users'])==verified['users']
    clients = {c['clientId']: c for c in realm['clients']}
    for name in ['zerotrust-provisioner', 'zerotrust-portal-risk-admin', 'zerotrust-risk-caller']:
        assert clients[name].get('secret'), 'MISSING_EXISTING_CLIENT_SECRET'
    original_root = json.loads(next(l.split('=', 1)[1] for l in
        (source / 'plan/risk-client.private.cnf').read_text().splitlines() if l.startswith('password=')))
    pw = {k: secrets.token_urlsafe(30) for k in ['school-root', 'school', 'school-migrator', 'keycloak-root', 'keycloak']}
    pw['risk-root'] = original_root
    pw['risk'] = env['RISK_DB_PASSWORD']
    pw['redis'] = (source / 'plan/redis-password.private').read_text()
    save(state / 'credentials.private.json', {'owner': PROJECT, 'passwords': pw})
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'ZeroTrust Legacy Integration CA')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(minutes=5))
          .not_valid_after(now+dt.timedelta(days=365)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
          .sign(ca_key, hashes.SHA256()))
    pem = ca.public_bytes(serialization.Encoding.PEM)
    save(state / 'authority/ca.key', ca_key.private_bytes(serialization.Encoding.PEM,
         serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())
    save(state / 'public-ca/ca.crt', pem.decode())
    (state / 'public-ca/ca.crt').chmod(0o644)
    crl = (x509.CertificateRevocationListBuilder().issuer_name(ca.subject).last_update(now)
           .next_update(now+dt.timedelta(days=7))
           .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
           .sign(ca_key, hashes.SHA256()))
    (state / 'public-ca/ca.crl').write_bytes(crl.public_bytes(serialization.Encoding.DER))
    (state / 'public-ca/ca.crl').chmod(0o644)
    roles = ['school', 'risk-db', 'keycloak-db', 'redis', 'backend', 'risk', 'gateway', 'keycloak', 'migrate']
    passwords = {}
    for role in roles:
        directory = state / role; directory.mkdir(exist_ok=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, role)]))
                .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=90))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(role), x509.DNSName('localhost')]), False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), False)
                .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
                .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier('http://crl:8080/ca.crl')], relative_name=None, reasons=None, crl_issuer=None)]), False)
                .sign(ca_key, hashes.SHA256()))
        password = secrets.token_urlsafe(24); passwords[role] = password
        save(directory / 'ca.crt', pem.decode())
        save(directory / 'server.crt', cert.public_bytes(serialization.Encoding.PEM).decode())
        save(directory / 'server.key', key.private_bytes(serialization.Encoding.PEM,
             serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())
        (directory / 'server.p12').write_bytes(pkcs12.serialize_key_and_certificates(
            b'server', key, cert, [ca], serialization.BestAvailableEncryption(password.encode())))
        save(directory / 'store-password', password)
        subprocess.run(['keytool', '-importcert', '-noprompt', '-alias', 'legacy-ca', '-file', str(directory/'ca.crt'),
                        '-keystore', str(directory/'trust.p12'), '-storetype', 'PKCS12',
                        '-storepass:file', str(directory/'store-password')], capture_output=True, check=True)
        save(directory / 'jvm.args', '-Djavax.net.ssl.trustStore=/run/demo/trust.p12\n-Djavax.net.ssl.trustStorePassword=' +
             password + '\n-Xmx256m\n')
        if role in ['backend', 'risk', 'gateway']:
            props(role, {'server.port': '8443', 'server.address': '0.0.0.0', 'server.ssl.enabled': 'true',
                         'server.ssl.key-store': 'file:/run/demo/server.p12', 'server.ssl.key-store-password': password,
                         'server.ssl.key-store-type': 'PKCS12', 'server.ssl.key-alias': 'server',
                         'server.ssl.enabled-protocols': 'TLSv1.2,TLSv1.3', 'server.forward-headers-strategy': 'none'})
    def extend(role, values):
        file = state / role / 'application.properties'
        previous = file.read_text(); props(role, values); file.write_text(previous+file.read_text())
    for role in ['school', 'risk-db', 'keycloak-db']:
        save(state/role/'server.cnf', '[mysqld]\nrequire_secure_transport=ON\nssl-ca=/run/demo/ca.crt\n'
             'ssl-cert=/run/demo/server.crt\nssl-key=/run/demo/server.key\ndefault-time-zone=+00:00\nevent_scheduler=OFF\n')
        save(state/role/'root-password', pw[role+'-root' if role != 'risk-db' else 'risk-root'] if role != 'keycloak-db' else pw['keycloak-root'])
        root = pw['school-root' if role=='school' else 'risk-root' if role=='risk-db' else 'keycloak-root']
        save(state/role/'client.cnf', '[client]\nuser=root\npassword="'+root+'"\nhost='+role+
             '\nssl-mode=VERIFY_IDENTITY\nssl-ca=/run/demo/ca.crt\n')
    save(state/'redis/redis-password', pw['redis'])
    save(state/'redis/redis.conf', 'bind 0.0.0.0\nport 0\ntls-port 6379\ntls-cert-file /run/demo/server.crt\n'
         'tls-key-file /run/demo/server.key\ntls-ca-cert-file /run/demo/ca.crt\ntls-auth-clients no\nrequirepass '+
         pw['redis']+'\nappendonly yes\nappendfsync everysec\n')
    extend('backend', {'spring.profiles.active': 'prod', 'spring.jpa.hibernate.ddl-auto': 'validate',
        'spring.datasource.url': 'jdbc:mysql://school:3306/vip_pro?sslMode=VERIFY_IDENTITY&serverTimezone=UTC',
        'spring.datasource.username': 'legacy_school', 'spring.datasource.password': pw['school'],
        'spring.security.oauth2.resourceserver.jwt.issuer-uri': ISSUER,
        'spring.security.oauth2.resourceserver.jwt.jwk-set-uri': 'https://keycloak:28444/realms/DoAn/protocol/openid-connect/certs',
        'app.security.cors.allowed-origins': ORIGIN, 'keycloak.admin.server-url': 'https://keycloak:28444',
        'keycloak.admin.realm': 'DoAn', 'keycloak.admin.client-id': 'zerotrust-provisioner',
        'keycloak.admin.client-secret': clients['zerotrust-provisioner']['secret'],
        'app.risk-admin.base-url': 'https://risk:8443',
        'app.risk-admin.token-uri': 'https://keycloak:28444/realms/DoAn/protocol/openid-connect/token',
        'app.risk-admin.client-id': 'zerotrust-portal-risk-admin',
        'app.risk-admin.client-secret': clients['zerotrust-portal-risk-admin']['secret']})
    extend('risk', {'risk.security.issuer-uri': ISSUER,
        'risk.security.jwk-set-uri': 'https://keycloak:28444/realms/DoAn/protocol/openid-connect/certs',
        'spring.datasource.url': 'jdbc:mysql://risk-db:3306/risk_db?sslMode=VERIFY_IDENTITY&serverTimezone=UTC',
        'spring.datasource.username': 'risk_service', 'spring.datasource.password': pw['risk'],
        # The separately approved job validates/applies immutable V5 before app start.
        'spring.jpa.hibernate.ddl-auto': 'validate', 'spring.flyway.enabled': 'false',
        'risk.device-fingerprint.pepper': env['RISK_DEVICE_FINGERPRINT_PEPPER'],
        'risk.authentication-history.pepper': env['RISK_AUTH_HISTORY_PEPPER'],
        'risk.authentication-history.key-prefix': env.get('RISK_AUTH_HISTORY_KEY_PREFIX', 'zerotrust:risk:auth-history'),
        'spring.data.redis.host': 'redis', 'spring.data.redis.port': '6379', 'spring.data.redis.password': pw['redis'],
        'spring.data.redis.ssl.enabled': 'true'})
    extend('gateway', {'app.routes.backend': 'https://backend:8443', 'app.routes.frontend': 'http://frontend:3000',
        'app.security.jwt.issuer': ISSUER, 'app.security.jwt.jwks': 'https://keycloak:28444/realms/DoAn/protocol/openid-connect/certs',
        'app.security.cors.origins': ORIGIN})
    save(state/'risk/legacy-policy.env', ''.join(k+'='+v+'\n' for k,v in env.items() if k.startswith(('RISK_NETWORK_', 'RISK_GEOIP_'))))
    save(state/'keycloak/keycloak.conf', 'db=mysql\ndb-url=jdbc:mysql://keycloak-db:3306/keycloak_legacy?sslMode=VERIFY_IDENTITY&serverTimezone=UTC\n'
         'db-username=legacy_keycloak\ndb-password='+pw['keycloak']+'\nhostname=https://localhost:28444\nhostname-strict=true\n'
         'http-enabled=false\nhttps-port=28444\nhttps-certificate-file=/run/demo/server.crt\nhttps-certificate-key-file=/run/demo/server.key\n'
         'truststore-paths=/run/demo/ca.crt\nhealth-enabled=true\n')
    save(state/'migrate/migration.properties', 'url=jdbc:mysql://risk-db:3306/risk_db?sslMode=VERIFY_IDENTITY&serverTimezone=UTC\n'
         'username=root\npassword='+pw['risk-root']+'\nwriter.username=risk_service\napproved.project='+PROJECT+
         '\nowner.execution.approved=false\n')
    save(state/'school/migration.private.json', {'project':PROJECT, 'host':'school', 'database':'vip_pro',
         'username':'legacy_school_migrator', 'password':pw['school-migrator'], 'ca':'/run/demo/ca.crt'})
    before = json.loads((source/'backups/school-baseline-before.private.json').read_text())
    baseline = {'tables':before['tables'], 'ddl':{}}
    for table, lines in before['ddl'].items():
        ddl = '\n'.join(lines).split('\t',1)[1]
        baseline['ddl'][table] = ddl.replace(' CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci',' COLLATE utf8mb4_unicode_ci')
    save(state/'school/baseline.private.json', baseline)
    for file in realm_dir.glob('*-realm.json'):
        save(state/'migration-inputs/keycloak/original-export'/file.name, file.read_text(encoding='utf-8'))
    save(state/'source-manifest.private.json', {'owner':PROJECT,
        'backups':{k:v['sha256'] for k,v in json.loads((source/'execution/backup-execution.private.json').read_text())['steps'].items()},
        'source_provider_sha256':hashlib.sha256((source/'keycloak-files/providers/keycloak-risk-extension.jar').read_bytes()).hexdigest(),
        'ca_sha256':hashlib.sha256(pem).hexdigest(), 'ca_windows_thumbprint_sha1':ca.fingerprint(hashes.SHA1()).hex().upper(),
        'issuer':ISSUER, 'portal_origin':ORIGIN, 'synthetic_users_created':0})
    save(marker, {'owner':PROJECT, 'format':1, 'persistent_execution_approved':False})
    print('Private legacy TLS/config/input references prepared. No database, realm import or synthetic seed executed.')


if __name__ == '__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,required=True);parser.add_argument('--state',type=Path,required=True)
    args=parser.parse_args();prepare(args.source,args.state)
