"""Prepare and operate the isolated, loopback-only Academic Demo."""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(ROOT / 'deploy/demo'), str(ROOT / 'deploy/public-demo')]
from fixtures import realm, school_seed
from render_ingress import load, render

PROJECT = 'zt-academic-demo'
SCOPE = 'academic-demo-local'
PORT = 19443
PORTAL_HOST = 'portal.academic-demo.test'
AUTH_HOST = 'auth.academic-demo.test'
PORTAL = f'https://{PORTAL_HOST}:{PORT}'
AUTH = f'https://{AUTH_HOST}:{PORT}'
REALM = 'academic-demo'
ISSUER = f'{AUTH}/realms/{REALM}'
JWK = ISSUER + '/protocol/openid-connect/certs'
TOKEN = ISSUER + '/protocol/openid-connect/token'
RISK = 'https://risk:8443'
SUBNET = ipaddress.ip_network('172.31.230.0/27')
VOLUMES = {f'{r}-config' for r in ('mysql','redis','keycloak','installer','risk','backend','gateway','migrate','ingress')} | {'mysql-data','redis-data','mysql-recovery-data'}
EXACT_IMAGES = {
    'zt-pd02-candidate/keycloak:pd-r11-c401e17': 'e06bec13a903df01c1fd80b590d328db99ecbc4b00ee6ce3baa6f10f5f142615',
    'zt-pd02-candidate/risk:pd-r12-c401e17': '122237b9480449be28aa55f717747d3f2cc00cd3e3a45cbeae66d83ee60e202a',
    'zt-pd02-candidate/portal:pd-r11-c401e17': 'e268a00ef8375fea37c5cd322f656ef424312aae78dc44ab589bc376336dbf45',
    'zt-pd02-candidate/gateway:pd-r11-c401e17': 'bf4491e134669996e6d1baaa9cf68e6f1c1b077433d7cee37ccf2add69b9e05f',
}
STATE = ROOT / 'target/academic-demo/private'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def docker(*args, check=True, timeout=420, data=None):
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith('COMPOSE_')}
    env['ACADEMIC_STATE'] = STATE.as_posix()
    p = subprocess.run(['docker', *args], env=env, input=data, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout)
    if p.returncode and check:
        raise RuntimeError(f'Docker {args[0]} action failed ({p.returncode}); check owned service status')
    return p


def compose(*args, **kwargs):
    return docker('compose', '-p', PROJECT, '-f', str(HERE / 'compose.academic-demo.yaml'), *args, **kwargs)


def verify_boundary():
    require(STATE.resolve()==STATE and STATE.parent.resolve()==STATE.parent, 'Unexpected private state path')
    require(not any(os.getenv(key) for key in ('DOCKER_HOST','DOCKER_CONTEXT')), 'Explicit remote Docker override present')
    context = docker('context', 'show').stdout.strip()
    endpoint = docker('context', 'inspect', '--format', '{{.Endpoints.docker.Host}}', context).stdout.strip()
    require(endpoint.startswith(('npipe:', 'unix:')), 'Local Docker endpoint required')
    require(docker('info','--format','{{.OSType}}').stdout.strip() == 'linux', 'Linux Docker engine required')
    ids = docker('ps','-aq','--filter',f'label=com.docker.compose.project={PROJECT}','--no-trunc').stdout.splitlines()
    volume_names = set(docker('volume','ls','-q').stdout.splitlines())
    if (STATE/'installed').is_file():
        require({PROJECT+'_'+name for name in VOLUMES-{'mysql-recovery-data'}} <= volume_names,
                'Installed profile volume missing; restore before startup')
    for name in volume_names:
        if not name.startswith(PROJECT + '_'):
            continue
        require(name.removeprefix(PROJECT + '_') in VOLUMES, 'Unexpected volume in Academic Demo namespace')
        label = docker('volume','inspect','--format','{{index .Labels "com.docker.compose.project"}}',name).stdout.strip()
        require(label == PROJECT, 'Foreign volume ownership')
    for name in docker('network','ls','--format','{{.Name}}').stdout.splitlines():
        owned = name in (PROJECT+'_core',PROJECT+'_edge',PROJECT+'_recovery')
        meta = json.loads(docker('network','inspect','--format','{{json .}}',name).stdout)
        labels = meta.get('Labels') or {}
        if owned:
            require(labels.get('com.docker.compose.project') == PROJECT, 'Foreign network ownership')
            require(set(meta.get('Containers') or {}) <= set(ids), 'Foreign container attached to Academic Demo network')
        else:
            for block in (meta.get('IPAM') or {}).get('Config') or []:
                cidr = block.get('Subnet')
                if cidr:
                    network = ipaddress.ip_network(cidr, strict=False)
                    require(network.version != 4 or not network.overlaps(SUBNET), 'Academic Demo subnet already in use')
    for ident in ids:
        labels = json.loads(docker('inspect','--format','{{json .Config.Labels}}',ident).stdout)
        require(labels.get('io.zerotrust.scope') == SCOPE, 'Foreign container ownership')
        mounts = json.loads(docker('inspect','--format','{{json .Mounts}}',ident).stdout)
        for mount in mounts:
            if mount['Type'] == 'volume':
                require(mount['Name'] in {PROJECT+'_'+name for name in VOLUMES}, 'Foreign volume attached')
            elif mount['Type'] == 'bind':
                require(labels['com.docker.compose.service'] == 'materialize' and not mount['RW'], 'Unexpected bind mount')
    for image, expected in EXACT_IMAGES.items():
        require(docker('image','inspect','--format','{{.Id}}',image).stdout.strip() == 'sha256:'+expected, 'Local baseline image digest mismatch')
    rendered = json.loads(compose('--profile','*','config','--format','json').stdout)
    published = [(name, entry) for name, svc in rendered['services'].items() for entry in svc.get('ports', [])]
    require(len(published) == 1 and published[0][0] == 'ingress'
            and published[0][1]['host_ip'] == '127.0.0.1'
            and str(published[0][1]['published']) == str(PORT), 'Loopback-only ingress required')
    require(rendered['networks']['core']['internal'] is True, 'Private network required')
    require(rendered['networks']['recovery']['internal'] is True, 'Recovery network must be private')
    require(set(rendered['volumes']) == VOLUMES and not any(v.get('external') for v in rendered['volumes'].values()),
            'Compose volume boundary mismatch')


def rnd():
    return secrets.token_urlsafe(32)


def save(role, name, value):
    file = STATE / role / name
    file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    file.write_bytes(value if isinstance(value, bytes) else value.encode())
    file.chmod(0o600)


def props(role, name, values):
    save(role, name, ''.join(f'{key}={value}\n' for key,value in values.items()))


def certs():
    now = dt.datetime.now(dt.timezone.utc)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = lambda value: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,value)])
    ca_name = name('ZeroTrust Academic Demo Local CA')

    def builder(key, subject, days):
        return (x509.CertificateBuilder().subject_name(name(subject)).issuer_name(ca_name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now-dt.timedelta(minutes=10)).not_valid_after(now+dt.timedelta(days=days))
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False))

    ca = (builder(root_key, 'ZeroTrust Academic Demo Local CA', 30)
          .add_extension(x509.BasicConstraints(ca=True,path_length=0),True)
          .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),True)
          .sign(root_key,hashes.SHA256()))
    pem = ca.public_bytes(serialization.Encoding.PEM)
    save('.', 'ca.crt', pem)
    for role, names in {'mysql':['mysql'],'redis':['redis'],'keycloak':[AUTH_HOST,'keycloak'],
                        'risk':['risk'],'backend':['backend'],'gateway':['gateway'],
                        'ingress':[PORTAL_HOST,AUTH_HOST]}.items():
        key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cert = (builder(key,names[0],21).add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(host) for host in names]),False)
                .add_extension(x509.KeyUsage(True,False,True,False,False,False,False,False,False),True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False)
                .sign(root_key,hashes.SHA256()))
        save(role,'ca.crt',pem)
        if role in ('risk','backend','gateway'):
            password = rnd()
            save(role,'server.p12',pkcs12.serialize_key_and_certificates(
                b'server',key,cert,[ca],serialization.BestAvailableEncryption(password.encode())))
            yield role,password
        else:
            save(role,'server.crt',cert.public_bytes(serialization.Encoding.PEM))
            save(role,'server.key',key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))


def jdbc(role):
    return f'jdbc:mysql://mysql:3306/pd_staging_{role}?sslMode=VERIFY_IDENTITY&serverTimezone=UTC'


def configure_db(pw, cfg):
    save('mysql','root-password',pw['root'])
    props('mysql','root.cnf', {'[client]\nuser':'root','password':pw['root'],'protocol':'socket'})
    props('mysql','school.cnf',{'[client]\nuser':'pd_staging_school_runtime','password':pw['school'],
          'host':'mysql','ssl-mode':'VERIFY_IDENTITY','ssl-ca':'/fixture/ca.crt','database':'pd_staging_school'})
    sql = []
    for schema in ('school','risk','keycloak'):
        collation = 'utf8mb4_0900_ai_ci' if schema == 'risk' else 'utf8mb4_unicode_ci'
        sql.append(f'CREATE DATABASE pd_staging_{schema} CHARACTER SET utf8mb4 COLLATE {collation};')
    for user,db,password,grant in (
        ('school_runtime','school','school',None),('risk_runtime','risk','risk','SELECT,INSERT,UPDATE,DELETE'),
        ('risk_migrator','risk','migrate','ALL'),('keycloak_runtime','keycloak','keycloak','SELECT,INSERT,UPDATE,DELETE'),
        ('keycloak_installer','keycloak','installer','ALL')):
        account = f"'pd_staging_{user}'@'%'"
        sql.append(f"CREATE USER {account} IDENTIFIED BY '{pw[password]}' REQUIRE SSL;")
        if grant:
            sql.append(f'GRANT {grant} ON pd_staging_{db}.* TO {account};')
    sql.append("GRANT SELECT ON performance_schema.threads TO 'pd_staging_risk_migrator'@'%';")
    sql.append('USE pd_staging_school;')
    schema = (ROOT/'database/schema.sql').read_text(encoding='utf-8')
    sql += [schema[schema.index('-- ========================================================='):],school_seed(cfg).replace('USE demo_school;','USE pd_staging_school;')]
    sql += [f"GRANT SELECT ON pd_staging_school.{table} TO 'pd_staging_school_runtime'@'%';"
            for table in ('users','students','student_classes','subjects','scores')]
    save('mysql','init.sql','\n'.join(sql))
    props('migrate','migration.properties',{'url':jdbc('risk'),'username':'pd_staging_risk_migrator','password':pw['migrate']})
    save('redis','password',pw['redis'])
    save('redis','redis.conf','bind 0.0.0.0\nport 0\ntls-port 6379\ntls-cert-file /fixture/server.crt\n'
         'tls-key-file /fixture/server.key\ntls-ca-cert-file /fixture/ca.crt\ntls-auth-clients no\n'
         'aclfile /fixture/users.acl\nappendonly yes\nappendfsync everysec\nmaxmemory 32mb\nmaxmemory-policy noeviction\n')
    acl = (ROOT/'deploy/public-demo/redis-acl-contract.conf').read_text(encoding='utf-8')
    rule = next(line for line in acl.splitlines() if line.startswith('user default '))
    save('redis','users.acl',rule.replace('__REQUIRED_RISK_REDIS_PASSWORD_SHA256__',hashlib.sha256(pw['redis'].encode()).hexdigest())+'\n')


def configure_auth(pw,cfg):
    doc = realm(cfg)
    doc.update(realm=REALM, ssoSessionIdleTimeout=1800, ssoSessionMaxLifespan=28800, revokeRefreshToken=True, refreshTokenMaxReuse=0)
    doc['authenticatorConfig'][0]['config'].update(riskServiceBaseUrl=RISK,tokenEndpointUrl=TOKEN,
        serviceClientSecret='',serviceClientSecretFile='/run/secrets/risk-caller-client-secret')
    for client in doc['clients']:
        if client['clientId']=='zerotrust-spa':
            client.update(redirectUris=[PORTAL+'/',PORTAL+'/silent-check-sso.html'],webOrigins=[PORTAL])
            client['attributes']['post.logout.redirect.uris']=PORTAL+'/'
    for actor in doc['users']:
        if actor.get('serviceAccountClientId')=='zerotrust-provisioner':
            actor['clientRoles']={'realm-management':['query-users']}
    for role in ('keycloak','installer'):
        opt = {'db':'mysql','db-url':jdbc('keycloak'),'db-username':'pd_staging_keycloak_'+('runtime' if role=='keycloak' else 'installer'),
               'db-password':pw[role],'hostname':AUTH,'hostname-strict':'true','http-enabled':'false',
               'https-port':PORT,'http-management-scheme':'http','https-certificate-file':'/run/secrets/server.crt',
               'https-certificate-key-file':'/run/secrets/server.key','truststore-paths':'/run/secrets/ca.crt',
               'health-enabled':'true','cache':'local','proxy-headers':'xforwarded','proxy-trusted-addresses':'172.31.230.9/32',
               'http-max-queued-requests':'64','http-pool-max-threads':'32'}
        if role=='keycloak':
            opt.update({'spi-connections-jpa--quarkus--migration-strategy':'validate','spi-connections-jpa--quarkus--initialize-empty':'false'})
        else:
            opt.update({'bootstrap-admin-username':'academic-operator','bootstrap-admin-password':pw['bootstrap']})
            for f in ('ca.crt','server.crt','server.key'):
                save(role,f,(STATE/'keycloak'/f).read_bytes())
        props(role,'keycloak.conf',opt)
        save(role,'risk-caller-client-secret',cfg['clients']['zerotrust-risk-caller'])
        save(role,'ready.sh',"exec 3<>/dev/tcp/127.0.0.1/9000\nprintf 'GET /health/ready HTTP/1.0\\r\\n\\r\\n' >&3\nread -r result <&3\n[[ $result == 'HTTP/1.'*' 200 '* ]]\n")
    save('installer',REALM+'-realm.json',json.dumps(doc))


def configure_apps(pw,cfg,stores):
    keytool = shutil.which('keytool')
    if not keytool:
        candidates = list((ROOT/'target/pd-02-02/toolchain/jdk').glob('*/bin/keytool.exe'))
        require(len(candidates)==1, 'JDK 17 keytool required')
        keytool = str(candidates[0])
    save('.','trust-password',pw['trust'])
    proc = subprocess.run([keytool,'-importcert','-noprompt','-alias','academic-ca','-file',str(STATE/'ca.crt'),
        '-storetype','PKCS12','-keystore',str(STATE/'trust.p12'),'-storepass:file',str(STATE/'trust-password')],capture_output=True)
    require(proc.returncode==0,'Unable to build private Java truststore')
    for role in ('risk','backend','gateway','migrate'):
        save(role,'trust.p12',(STATE/'trust.p12').read_bytes())
        save(role,'jvm.args',f'-Djavax.net.ssl.trustStore=/run/demo/trust.p12\n-Djavax.net.ssl.trustStoreType=PKCS12\n-Djavax.net.ssl.trustStorePassword={pw["trust"]}\n-Xms64m\n-Xmx256m\n-XX:ActiveProcessorCount=2\n')
        if role=='migrate':
            continue
        opt = {'spring.profiles.active':'public-demo','app.public-demo.mode':'public-demo',
               'app.public-demo.academic-read-only':'true','app.public-demo.environment':'staging',
               'server.address':'0.0.0.0','server.port':'8443','server.ssl.enabled':'true',
               'server.ssl.key-store':'file:/run/demo/server.p12','server.ssl.key-store-type':'PKCS12',
               'server.ssl.key-store-password':stores[role],'server.ssl.key-alias':'server','server.forward-headers-strategy':'none'}
        if role in ('risk','backend'):
            schema = 'risk' if role=='risk' else 'school'
            opt.update({'spring.datasource.url':jdbc(schema),'spring.datasource.username':f'pd_staging_{schema}_runtime',
                        'spring.datasource.password':pw[schema]})
        if role=='risk':
            opt.update({'risk.security.issuer-uri':ISSUER,'risk.security.jwk-set-uri':JWK,
                'spring.data.redis.host':'redis','spring.data.redis.password':pw['redis'],
                'risk.device-fingerprint.pepper':pw['device'],'risk.authentication-history.pepper':pw['history'],
                'risk.policy.network-risk.enabled':'true',
                'risk.policy.network-risk.trusted-cidrs':'198.51.100.0/25',
                'risk.policy.network-risk.high-risk-cidrs':'203.0.113.0/24',
                'risk.policy.priority-rules.blocked-ip-addresses':'192.0.2.99'})
        elif role=='backend':
            opt.update({'spring.security.oauth2.resourceserver.jwt.issuer-uri':ISSUER,'spring.security.oauth2.resourceserver.jwt.jwk-set-uri':JWK,
                'keycloak.admin.server-url':AUTH,'keycloak.admin.realm':REALM,'keycloak.admin.client-id':'zerotrust-provisioner',
                'keycloak.admin.client-secret':cfg['clients']['zerotrust-provisioner'],'app.security.cors.allowed-origins':PORTAL,
                'app.risk-admin.base-url':RISK,'app.risk-admin.token-uri':TOKEN,'app.risk-admin.client-id':'zerotrust-portal-risk-admin',
                'app.risk-admin.client-secret':cfg['clients']['zerotrust-portal-risk-admin']})
        else:
            opt.update({'app.routes.backend':'https://backend:8443','app.routes.frontend':'http://frontend:3000',
                        'app.security.jwt.issuer':ISSUER,'app.security.jwt.jwks':JWK,'app.security.cors.origins':PORTAL,
                        'app.abuse.trusted-proxies':'172.31.230.9/32'})
        props(role,'application.properties',opt)


def prepare():
    if STATE.exists():
        require((STATE/'owner').is_file() and (STATE/'owner').read_text()==SCOPE, 'Incomplete or foreign private state')
        return
    require(STATE.resolve()==STATE and STATE.parent.resolve()==STATE.parent, 'Unexpected private state path')
    STATE.mkdir(mode=0o700, parents=True)
    if os.name == 'nt':
        principal = subprocess.check_output(['whoami'],text=True).strip()
        p = subprocess.run(['icacls',str(STATE),'/inheritance:r','/grant:r',principal+':(OI)(CI)F'],capture_output=True)
        require(p.returncode==0,'Unable to restrict private state ACL')
    pw = {key:rnd() for key in ('root','school','risk','migrate','keycloak','installer','redis','bootstrap','device','history','trust')}
    cfg = {'namespace':str(uuid.uuid4()),'clients':{r:rnd() for r in ('zerotrust-risk-caller','zerotrust-portal-risk-admin','zerotrust-provisioner')},
           'users':{r:{'id':str(uuid.uuid4()),'role':role,'username':'academic-'+r.replace('_','-'),'password':rnd()}
                    for r,role in [('admin','ADMIN'),('student_a','STUDENT'),('student_b','STUDENT')]}}
    stores = dict(certs())
    configure_db(pw,cfg)
    configure_auth(pw,cfg)
    configure_apps(pw,cfg,stores)
    ingress = load(ROOT/'deploy/public-demo/ingress-contract.json')
    ingress.update(listen_port=8443,portal_host=PORTAL_HOST,auth_host=AUTH_HOST,realm=REALM,
        certificate='/run/demo/server.crt',certificate_key='/run/demo/server.key',upstream_ca='/run/demo/ca.crt',
        gateway={'url':'https://gateway:8443','tls_name':'gateway'},
        keycloak={'url':f'https://keycloak:{PORT}','tls_name':AUTH_HOST})
    nginx = render(ingress).replace('pid logs/nginx.pid;','pid /tmp/nginx.pid;').replace('error_log logs/error.log crit;','error_log stderr crit;')
    nginx = nginx.replace('X-Forwarded-Port 443;',f'X-Forwarded-Port {PORT};')
    save('ingress','nginx.conf',nginx)
    save('.','accounts.json',json.dumps(cfg['users']))
    save('.','owner',SCOPE)
    print('Fresh isolated CA, service credentials and synthetic fixtures prepared.')


def start():
    verify_boundary()
    prepare()
    if not (STATE/'installed').is_file():
        compose('run','--rm','--no-deps','materialize')
        compose('up','-d','--wait','--wait-timeout','155','mysql','redis')
        writers = compose('exec','-T','mysql','mysql','--defaults-extra-file=/fixture/root.cnf','-Nse',
            "SELECT COUNT(*) FROM performance_schema.threads WHERE PROCESSLIST_USER='pd_staging_risk_runtime'").stdout.strip()
        require(writers=='0','Risk runtime writers present before migration')
        compose('run','--rm','--no-deps','migrate')
        ledger = compose('exec','-T','mysql','mysql','--defaults-extra-file=/fixture/root.cnf','-Nse',
            "SELECT checksum,success FROM pd_staging_risk.flyway_schema_history WHERE version='5'").stdout.strip()
        require(ledger=='661092940\t1','V5 ledger validation failed')
        compose('up','-d','--wait','--wait-timeout','140','keycloak-init')
        compose('stop','--timeout','35','keycloak-init')
        save('.','installed',SCOPE)
        print('Synthetic MySQL V1–V5 and Keycloak realm installed.')
    compose('up','-d','--wait','--wait-timeout','180')
    print('Academic Demo services reached healthy status.')
    print(PORTAL)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('prepare','start','status','stop'))
    action=parser.parse_args().action
    if action=='start':
        start()
    else:
        verify_boundary()
        if action=='prepare':
            prepare()
        elif action=='status':
            print(compose('ps','-a').stdout,end='')
        elif action=='stop':
            compose('stop','ingress','gateway','frontend','backend','risk','keycloak','redis','mysql')


if __name__=='__main__':
    main()
