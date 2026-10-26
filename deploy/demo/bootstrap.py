"""Owned zerotrust-demo bootstrap. Fresh secrets; no QA input or destructive reset."""
from fixtures import ident, school_seed, realm
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import uuid

ROOT = Path('/state')
ISSUER = 'https://localhost:8444/realms/zerotrust-demo'


def save(path, value, uid=0):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) if isinstance(value, (dict, list)) else value, encoding='utf-8')
    path.chmod(0o600)
    os.chown(path, uid, uid)


def props(role, values):
    save(ROOT / role / 'application.properties', ''.join(f'{k}={v}\n' for k, v in values.items()), 10001)


def permissions():
    for role,uid in [('mysql',999),('redis',999),('keycloak',1000),('backend',10001),('risk',10001),('gateway',10001),('migrate',10001)]:
        for path in (ROOT/role).rglob('*'):
            assert not path.is_symlink(), 'UNEXPECTED_STATE_SYMLINK'
            if path.is_file():
                os.chown(path,uid,uid)
                path.chmod(0o600)


def refresh_crl():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    key=serialization.load_pem_private_key((ROOT/'authority/ca.key').read_bytes(),None)
    ca=x509.load_pem_x509_certificate((ROOT/'ca.crt').read_bytes());now=dt.datetime.now(dt.timezone.utc)
    crl=(x509.CertificateRevocationListBuilder().issuer_name(ca.subject).last_update(now-dt.timedelta(minutes=5))
         .next_update(now+dt.timedelta(days=7)).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),False)
         .add_extension(x509.CRLNumber(int(now.timestamp())),False).sign(key,hashes.SHA256()))
    p=ROOT/'public-ca/ca.crl';p.parent.mkdir(exist_ok=True);p.write_bytes(crl.public_bytes(serialization.Encoding.DER));p.chmod(0o644)


def enable_crl():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
    key=serialization.load_pem_private_key((ROOT/'authority/ca.key').read_bytes(),None)
    ca=x509.load_pem_x509_certificate((ROOT/'ca.crt').read_bytes())
    for role,uid in [('mysql',999),('redis',999),('keycloak',1000),('backend',10001),('risk',10001),('gateway',10001),('migrate',10001)]:
        directory=ROOT/role;cert=x509.load_pem_x509_certificate((directory/'server.crt').read_bytes())
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:raise AssertionError('LEAF_REQUIRED')
        if any(isinstance(e.value,x509.CRLDistributionPoints) for e in cert.extensions):continue
        builder=(x509.CertificateBuilder().subject_name(cert.subject).issuer_name(cert.issuer).public_key(cert.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(cert.not_valid_before_utc).not_valid_after(cert.not_valid_after_utc))
        for extension in cert.extensions:builder=builder.add_extension(extension.value,extension.critical)
        builder=builder.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier('http://localhost:8445/ca.crl')],relative_name=None,reasons=None,crl_issuer=None)]),False)
        replacement=builder.sign(key,hashes.SHA256());leaf_key=serialization.load_pem_private_key((directory/'server.key').read_bytes(),None)
        save(directory/'server.crt',replacement.public_bytes(serialization.Encoding.PEM).decode(),uid)
        pwd=(directory/'store-password').read_text().encode();(directory/'server.p12').write_bytes(pkcs12.serialize_key_and_certificates(b'server',leaf_key,replacement,[ca],serialization.BestAvailableEncryption(pwd)))
    refresh_crl();permissions()
    print('Demo leaf certificates now advertise signed local CRL; CA and private keys preserved.')


def prepare():
    marker = ROOT / 'owner.json'
    if marker.exists():
        assert json.loads(marker.read_text()) == {'owner': 'zerotrust-demo', 'format': 1}
        assert (ROOT / 'credentials.json').exists(), 'INCOMPLETE_LOCAL_STATE'
        permissions()
        refresh_crl()
        print('Existing zerotrust-demo private configuration retained; no reseed/reset.')
        return
    assert not (ROOT / 'credentials.json').exists(), 'PARTIAL_BOOTSTRAP_REVIEW_REQUIRED'
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    now = dt.datetime.now(dt.timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'ZeroTrust Demo Local CA')])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=True,path_length=0),True)
          .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),False).sign(key, hashes.SHA256()))
    ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    save(ROOT/'authority/ca.key',key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode())
    save(ROOT/'ca.crt',ca_pem.decode());(ROOT/'ca.crt').chmod(0o644)
    cfg = {'owner':'zerotrust-demo','realm':'zerotrust-demo','namespace':str(uuid.uuid4()),
           'passwords':{k:secrets.token_urlsafe(30) for k in ['root','keycloak','risk','school','migrator','redis','bootstrap','pepper','history']},
           'clients':{k:secrets.token_urlsafe(32) for k in ['zerotrust-risk-caller','zerotrust-portal-risk-admin','zerotrust-provisioner']},'users':{}}
    for actor, role in [('student','STUDENT'),('student_b','STUDENT'),('teacher','TEACHER'),('teacher_b','TEACHER'),('admin','ADMIN'),('high','STUDENT')]:
        cfg['users'][actor]={'id':str(uuid.uuid5(uuid.UUID(cfg['namespace']),actor)), 'username':'demo_'+actor,
                             'password':secrets.token_urlsafe(20), 'role':role}
    for role, uid in [('mysql',999),('redis',999),('keycloak',1000),('backend',10001),('risk',10001),('gateway',10001),('migrate',10001)]:
        directory = ROOT/role;directory.mkdir(parents=True,exist_ok=True)
        leaf_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,role)]))
                .issuer_name(ca.subject).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=180))
                .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
                .add_extension(x509.KeyUsage(True,False,True,False,False,False,False,False,False),True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH,ExtendedKeyUsageOID.CLIENT_AUTH]),False)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(role),x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1')),x509.IPAddress(ipaddress.ip_address('::1'))]),False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),False).sign(key,hashes.SHA256()))
        pwd=secrets.token_urlsafe(24)
        save(directory/'store-password',pwd,uid)
        save(directory/'ca.crt',ca_pem.decode(),uid)
        save(directory/'server.crt',leaf.public_bytes(serialization.Encoding.PEM).decode(),uid)
        save(directory/'server.key',leaf_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode(),uid)
        store=directory/'server.p12';store.write_bytes(pkcs12.serialize_key_and_certificates(b'server',leaf_key,leaf,[ca],serialization.BestAvailableEncryption(pwd.encode())));store.chmod(0o600);os.chown(store,uid,uid)
        subprocess.run(['keytool','-importcert','-noprompt','-alias','demo-ca','-file',str(directory/'ca.crt'),'-keystore',str(directory/'trust.p12'),'-storetype','PKCS12','-storepass:file',str(directory/'store-password')],capture_output=True,check=True)
        os.chown(directory/'trust.p12',uid,uid);(directory/'trust.p12').chmod(0o600)
        save(directory/'jvm.args',f'-Djavax.net.ssl.trustStore=/run/demo/trust.p12\n-Djavax.net.ssl.trustStorePassword={pwd}\n-Xmx256m\n',uid)
        if role in ['backend','risk','gateway']:
            props(role,{'server.port':'8443','server.address':'0.0.0.0','server.ssl.enabled':'true','server.ssl.key-store':'file:/run/demo/server.p12',
                        'server.ssl.key-store-password':pwd,'server.ssl.key-store-type':'PKCS12','server.ssl.key-alias':'server',
                        'server.ssl.enabled-protocols':'TLSv1.2,TLSv1.3','server.forward-headers-strategy':'none'})
    save(ROOT/'credentials.json',cfg)
    pw=cfg['passwords']
    save(ROOT/'mysql/root-password',pw['root']);save(ROOT/'mysql/client.cnf',f'[client]\nuser=root\npassword={pw["root"]}\nhost=localhost\nssl-mode=VERIFY_IDENTITY\nssl-ca=/run/demo/ca.crt\n')
    save(ROOT/'mysql/server.cnf','[mysqld]\nrequire_secure_transport=ON\nssl-ca=/run/demo/ca.crt\nssl-cert=/run/demo/server.crt\nssl-key=/run/demo/server.key\ndefault-time-zone=+00:00\n')
    sql=''
    for database in ['demo_keycloak','demo_risk_app','demo_school']:
        collation='utf8mb4_0900_ai_ci' if database=='demo_risk_app' else 'utf8mb4_unicode_ci'
        sql+=f'CREATE DATABASE `{database}` CHARACTER SET utf8mb4 COLLATE {collation};\n'
    for user,database,password,grant in [('demo_keycloak','demo_keycloak',pw['keycloak'],'ALL'),('demo_risk','demo_risk_app',pw['risk'],'SELECT,INSERT,UPDATE'),('demo_school','demo_school',pw['school'],'SELECT,INSERT,UPDATE,DELETE'),('demo_migrator','demo_risk_app',pw['migrator'],'ALL')]:
        sql+=f"CREATE USER '{user}'@'%' IDENTIFIED BY '{password}' REQUIRE SSL; GRANT {grant} ON `{database}`.* TO '{user}'@'%';\n"
    sql+="GRANT SELECT ON performance_schema.threads TO 'demo_migrator'@'%';\nUSE demo_school;\n"
    schema=Path('/source/database/schema.sql').read_text();schema=schema[schema.index('-- ========================================================='):]
    sql+=schema+'\n'+Path('/source/database/migrate_teacher_assignment_schedule.sql').read_text()+'\n'+school_seed(cfg)
    save(ROOT/'mysql/10-demo.sql',sql)
    save(ROOT/'redis/redis.conf',f'bind 0.0.0.0\nport 0\ntls-port 6379\ntls-cert-file /run/demo/server.crt\ntls-key-file /run/demo/server.key\ntls-ca-cert-file /run/demo/ca.crt\ntls-auth-clients no\nrequirepass {pw["redis"]}\nappendonly yes\nappendfsync everysec\n')
    save(ROOT/'redis/redis-password',pw['redis'],999)
    jwt={'spring.security.oauth2.resourceserver.jwt.issuer-uri':ISSUER,'spring.security.oauth2.resourceserver.jwt.jwk-set-uri':'https://keycloak:8444/realms/zerotrust-demo/protocol/openid-connect/certs','app.security.cors.allowed-origins':'https://localhost:8443'}
    extend('backend',{**jwt,'spring.profiles.active':'prod','spring.datasource.url':'jdbc:mysql://mysql:3306/demo_school?sslMode=VERIFY_IDENTITY&serverTimezone=UTC',
        'spring.datasource.username':'demo_school','spring.datasource.password':pw['school'],'spring.jpa.hibernate.ddl-auto':'validate',
        'keycloak.admin.server-url':'https://keycloak:8444','keycloak.admin.realm':'zerotrust-demo','keycloak.admin.client-id':'zerotrust-provisioner','keycloak.admin.client-secret':cfg['clients']['zerotrust-provisioner'],
        'app.risk-admin.base-url':'https://risk:8443','app.risk-admin.token-uri':'https://keycloak:8444/realms/zerotrust-demo/protocol/openid-connect/token','app.risk-admin.client-id':'zerotrust-portal-risk-admin','app.risk-admin.client-secret':cfg['clients']['zerotrust-portal-risk-admin']})
    extend('risk',{'risk.security.issuer-uri':ISSUER,'risk.security.jwk-set-uri':'https://keycloak:8444/realms/zerotrust-demo/protocol/openid-connect/certs',
        'spring.datasource.url':'jdbc:mysql://mysql:3306/demo_risk_app?sslMode=VERIFY_IDENTITY&serverTimezone=UTC','spring.datasource.username':'demo_risk','spring.datasource.password':pw['risk'],
        'risk.device-fingerprint.pepper':pw['pepper'],'risk.authentication-history.pepper':pw['history'],'risk.authentication-history.key-prefix':'zerotrust-demo:auth-history',
        'spring.data.redis.host':'redis','spring.data.redis.port':'6379','spring.data.redis.password':pw['redis'],'spring.data.redis.ssl.enabled':'true',
        'risk.policy.network-risk.enabled':'true','risk.policy.network-risk.trusted-cidrs':'127.0.0.1/32,::1/128,172.30.80.0/25','risk.policy.network-risk.high-risk-cidrs':'172.30.80.192/27'})
    extend('gateway',{'app.routes.backend':'https://backend:8443','app.routes.frontend':'http://frontend:3000','app.security.jwt.issuer':ISSUER,
        'app.security.jwt.jwks':'https://keycloak:8444/realms/zerotrust-demo/protocol/openid-connect/certs','app.security.cors.origins':'https://localhost:8443'})
    save(ROOT/'migrate/migration.properties',f'url=jdbc:mysql://mysql:3306/demo_risk_app?sslMode=VERIFY_IDENTITY&serverTimezone=UTC\nusername=demo_migrator\npassword={pw["migrator"]}\n',10001)
    save(ROOT/'keycloak/bootstrap-password',pw['bootstrap'],1000)
    save(ROOT/'keycloak/keycloak.conf',f'db=mysql\ndb-url=jdbc:mysql://mysql:3306/demo_keycloak?sslMode=VERIFY_IDENTITY&serverTimezone=UTC\ndb-username=demo_keycloak\ndb-password={pw["keycloak"]}\nhostname=https://localhost:8444\nhostname-strict=true\nhttp-enabled=false\nhttps-port=8444\nhttps-certificate-file=/run/demo/server.crt\nhttps-certificate-key-file=/run/demo/server.key\ntruststore-paths=/run/demo/ca.crt\nhealth-enabled=true\n',1000)
    save(ROOT/'keycloak/realm/demo-realm.json',realm(cfg),1000)
    enable_crl()
    save(marker,{'owner':'zerotrust-demo','format':1})
    print('Fresh demo CA, service credentials, realm and synthetic School dataset prepared; values remain private.')


def extend(role, values):
    path=ROOT/role/'application.properties'
    save(path,path.read_text()+''.join(f'{k}={v}\n' for k,v in values.items()),10001)


if __name__=='__main__':
    try:
        if sys.argv[1]=='prepare':prepare()
        elif sys.argv[1]=='enable-crl':enable_crl()
        else:raise ValueError('UNKNOWN_BOOTSTRAP_ACTION')
    except Exception as error:
        print('Demo bootstrap failed: '+(str(error) if isinstance(error,AssertionError) else type(error).__name__),file=sys.stderr)
        sys.exit(1)
