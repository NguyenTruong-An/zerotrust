"""Isolated full-business synthetic DoAn profile; does not promote an RC release."""
import argparse
import datetime as dt
import ipaddress
import json
import os
import re
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT/'deploy/academic-linux/rc'))
import rc
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

base = rc.base
PROJECT = 'zt-full-function-20261111b'
OUT = ROOT/'target/full-function-20261111b'
STATE = OUT/'private'
PORT = 39443
SUBNET = '10.253.245.0/27'
PROXY_IP = str(ipaddress.ip_network(SUBNET).network_address + 25)
HIGH_TEST_IP = str(ipaddress.ip_network(SUBNET).network_address + 27)
PORTAL_HOST = 'portal.full-function.test'
AUTH_HOST = 'auth.full-function.test'
FRONTEND = 'zt-full-function/frontend:20261111-1'
EXPECTED = {
    'keycloak': ('zt-security-candidate/keycloak:20261110-1', 'sha256:29f942de9bfd6b2823d9922ebf13790bdb6519e0a70b3276a076324fe91b9085'),
    'mysql84': ('zt-security-candidate/mysql84:20261110-1', 'sha256:8afece5fe884d21fc2944b5f200daa9c94a00ba98c196a5765ae2bb665a7ee80'),
    'mysql80': ('zt-security-candidate/mysql80:20261110-1', 'sha256:1c9444499b0ab9000f008ce719c7fc2c2c279c97aae542356c9a1a7c03819f5d'),
}


def run(*args, data=None, timeout=300, check=True):
    p = subprocess.run(args, input=data, capture_output=True, encoding='utf-8',
                       timeout=timeout, cwd=ROOT)
    if check and p.returncode:
        raise RuntimeError(f'{args[0]} {args[1]} failed ({p.returncode}); secret output withheld')
    return p


def check(value, text):
    if not value:
        raise RuntimeError(text)


def certs():
    """Fresh CA/key/CRL only. Nothing from legacy PKI is copied or renewed."""
    now = dt.datetime.now(dt.timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = lambda text: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])
    ca_name = name('ZeroTrust Full Function Synthetic CA')
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-dt.timedelta(minutes=10)).not_valid_after(now+dt.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
          .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False), True)
          .sign(key, hashes.SHA256()))
    crl = (x509.CertificateRevocationListBuilder().issuer_name(ca_name)
           .last_update(now-dt.timedelta(minutes=5)).next_update(now+dt.timedelta(days=7))
           .add_extension(x509.CRLNumber(1), False).sign(key, hashes.SHA256()))
    pem = ca.public_bytes(serialization.Encoding.PEM)
    crl_pem = crl.public_bytes(serialization.Encoding.PEM)
    base.save('.', 'ca.crt', pem)
    base.save('.', 'ca.key', key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    base.save('.', 'ca.crl.pem', crl_pem)
    base.save('.', 'ca-with-crl.pem', pem+crl_pem)
    base.save('ingress', 'ca.crl', crl.public_bytes(serialization.Encoding.DER))
    base.save('crl', 'ca.crl', crl.public_bytes(serialization.Encoding.DER))
    base.save('ingress', 'ca.crl.pem', crl_pem)
    base.save('ingress', 'ca-with-crl.pem', pem+crl_pem)
    hosts = {'mysql':['mysql'], 'redis':['redis'], 'keycloak':[AUTH_HOST,'keycloak'],
             'risk':['risk'], 'backend':['backend'], 'gateway':['gateway'],
             'ingress':[PORTAL_HOST,AUTH_HOST]}
    for role, dns in hosts.items():
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf = (x509.CertificateBuilder().subject_name(name(dns[0])).issuer_name(ca_name)
                .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=14))
                .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(x) for x in dns]),False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),False)
                .add_extension(x509.KeyUsage(True,False,True,False,False,False,False,False,False),True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False)
                .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                    [x509.UniformResourceIdentifier('http://crl.full-function.test:39445/ca.crl')],None,None,None)]),False)
                .sign(key,hashes.SHA256()))
        base.save(role,'ca.crt',pem)
        base.save(role,'server.crt',leaf.public_bytes(serialization.Encoding.PEM))
        if role in ('risk','backend','gateway'):
            password = base.rnd()
            base.save(role,'server.p12',pkcs12.serialize_key_and_certificates(
                b'server',leaf_key,leaf,[ca],serialization.BestAvailableEncryption(password.encode())))
            yield role,password
        else:
            base.save(role,'server.key',leaf_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))


def prepare():
    check(not STATE.exists(), 'Existing private state must not be overwritten')
    original_certs, original_apps, original_auth, original_db = base.certs, base.configure_apps, base.configure_auth, base.configure_db

    def db(pw, cfg):
        original_db(pw, cfg)
        path = STATE/'mysql/init.sql'
        base.save('mysql','init.sql',path.read_text()+"\nGRANT SELECT,INSERT,UPDATE,DELETE ON pd_staging_school.* TO 'pd_staging_school_runtime'@'%';\n")

    def auth(pw, cfg):
        original_auth(pw, cfg)
        path = STATE/'installer/DoAn-realm.json'
        doc = json.loads(path.read_text())
        doc.update(adminEventsEnabled=True,adminEventsDetailsEnabled=False)
        flow_contract=json.loads((HERE/'auth-flow-contract.json').read_text(encoding='utf-8'))
        doc['browserFlow']=flow_contract['browserFlow']
        doc['authenticationFlows']=flow_contract['authenticationFlows']
        for client in doc['clients']:
            if client['clientId']=='zerotrust-provisioner':
                # Keycloak 26.8.2 enforces BOTH the built-in scope and its Admin API audience.
                # This grants no additional role and is deliberately absent from the SPA.
                client['defaultClientScopes']=['basic','profile','email','roles','kc-admin-api']
        for user in doc['users']:
            if user.get('serviceAccountClientId') == 'zerotrust-provisioner':
                user['clientRoles']={'realm-management':['manage-users','view-users','query-users','view-clients','view-realm']}
        doc['requiredActions'] = [{'alias':a,'name':a,'providerId':a,'enabled':True,'defaultAction':False,'priority':i*10,'config':{}}
                                  for i,a in enumerate(('CONFIGURE_TOTP','CONFIGURE_RECOVERY_AUTHN_CODES','UPDATE_PASSWORD','VERIFY_EMAIL'))]
        base.save('installer',path.name,json.dumps(doc))
        for role in ('keycloak','installer'):
            p=STATE/role/'keycloak.conf'
            text=p.read_text().replace(f'https-port={PORT}', 'https-port=8443').replace('172.31.230.9/32',PROXY_IP+'/32')
            text='\n'.join(x for x in text.splitlines() if not x.startswith('bootstrap-admin-'))+'\n'
            base.save(role,'keycloak.conf',text)

    def apps(pw, cfg, stores):
        original_apps(pw, cfg, stores)
        for role in ('risk','backend','gateway'):
            p=STATE/role/'application.properties'
            text=p.read_text().replace('172.31.230.9/32',PROXY_IP+'/32')
            if role=='backend':
                text=text.replace('spring.profiles.active=public-demo','spring.profiles.active=full-function')
                text=text.replace('app.public-demo.mode=public-demo','app.public-demo.mode=lab')
                text=text.replace('app.public-demo.academic-read-only=true','app.public-demo.academic-read-only=')
                text=text.replace('keycloak.admin.server-url='+base.AUTH,'keycloak.admin.server-url=https://keycloak:8443')
                text+='spring.jpa.hibernate.ddl-auto=validate\nspring.jpa.generate-ddl=false\nspring.sql.init.mode=never\nspring.datasource.hikari.read-only=false\n'
            elif role=='risk':
                # A dedicated disposable helper uses this actual source address for HIGH acceptance.
                # No forwarded header spoofing, threshold change, or live-user network policy change.
                text=text.replace('risk.policy.network-risk.high-risk-cidrs=203.0.113.0/24',
                                  'risk.policy.network-risk.high-risk-cidrs=203.0.113.0/24,'+HIGH_TEST_IP+'/32')
            base.save(role,p.name,text)
        for role in ('risk','backend','gateway','migrate'):
            p=STATE/role/'jvm.args'
            base.save(role,p.name,p.read_text()+'-Dcom.sun.net.ssl.checkRevocation=true\n-Dcom.sun.security.enableCRLDP=true\n')

    try:
        base.certs,base.configure_apps,base.configure_auth,base.configure_db = certs,apps,auth,db
        base.prepare()
    finally:
        base.certs,base.configure_apps,base.configure_auth,base.configure_db = original_certs,original_apps,original_auth,original_db
    ingress=base.load(ROOT/'deploy/public-demo/ingress-contract.json')
    ingress.update(listen_port=PORT,portal_host=PORTAL_HOST,auth_host=AUTH_HOST,realm='DoAn',
                   certificate='/run/demo/server.crt',certificate_key='/run/demo/server.key',upstream_ca='/run/demo/ca.crt',
                   gateway={'url':'https://gateway:8443','tls_name':'gateway'},keycloak={'url':'https://keycloak:8443','tls_name':AUTH_HOST})
    text=base.render(ingress).replace('pid logs/nginx.pid;','pid /tmp/nginx.pid;').replace('error_log logs/error.log crit;','error_log stderr crit;')
    text=text.replace('X-Forwarded-Port 443;',f'X-Forwarded-Port {PORT};')
    text=text.replace('proxy_ssl_verify on;','proxy_ssl_verify on;\nproxy_ssl_crl /run/demo/ca.crl.pem;')
    base.save('ingress','nginx.conf',text)
    base.save('ingress','edge-ca.crt',(STATE/'ca.crt').read_bytes())
    base.save('crl','crl.conf','worker_processes 1; pid /tmp/crl.pid; error_log stderr crit; events { worker_connections 64; } http { access_log off; server { listen 39445; location = /ca.crl { root /run/demo; default_type application/pkix-crl; } location / { return 404; } } }\n')


def configure():
    # Fail before Compose/receipt writes if Risk was promoted out of band. Legacy
    # restart/install commands must never silently revert a promoted profile.
    from risk_promotion import assert_legacy_runtime
    assert_legacy_runtime(ROOT)
    OUT.mkdir(parents=True,exist_ok=True)
    check(run('docker','info','--format','{{.OSType}}').stdout.strip()=='linux','Linux Docker required')
    check(not os.environ.get('DOCKER_HOST') and not os.environ.get('DOCKER_CONTEXT'),'Remote Docker override rejected')
    context=run('docker','context','show').stdout.strip()
    endpoint=run('docker','context','inspect','--format','{{.Endpoints.docker.Host}}',context).stdout.strip()
    check(endpoint.startswith(('npipe:','unix:')),'Run on the host local Docker daemon only')
    baseline=json.loads((ROOT/'target/pd-r27/release-lock.json').read_text())
    images={k:v['image'] for k,v in baseline['builds'].items()}
    ids={v['image']:v['id'] for v in baseline['builds'].values() if v['image']!=images['frontend'] and v['image']!=images['keycloak']}
    images.update(keycloak=EXPECTED['keycloak'][0],frontend=FRONTEND)
    ids.update({ref:ident for ref,ident in EXPECTED.values()})
    for ref,ident in ids.items():
        check(run('docker','image','inspect','--format','{{.Id}} {{.Os}}/{{.Architecture}}',ref).stdout.strip()==ident+' linux/amd64','Exact image mismatch: '+ref)
    front=run('docker','image','inspect','--format','{{.Id}} {{.Os}}/{{.Architecture}}',FRONTEND).stdout.strip().split()
    check(front[1]=='linux/amd64','Frontend architecture mismatch')
    ids[FRONTEND]=front[0]
    c={'state':STATE,'state_dir':str(STATE),'schema_env':'staging','mode':'full-function'}
    base.STATE=STATE;base.PROJECT=base.SCOPE=PROJECT;base.SUBNET=ipaddress.ip_network(SUBNET)
    base.PORT=PORT;base.PORTAL_HOST=PORTAL_HOST;base.AUTH_HOST=AUTH_HOST;base.REALM='DoAn'
    base.PORTAL=f'https://{PORTAL_HOST}:{PORT}';base.AUTH=f'https://{AUTH_HOST}:{PORT}'
    base.ISSUER=base.AUTH+'/realms/DoAn';base.JWK='https://keycloak:8443/realms/DoAn/protocol/openid-connect/certs'
    base.TOKEN='https://keycloak:8443/realms/DoAn/protocol/openid-connect/token'
    base.VOLUMES.update(('mysql-bootstrap-data','crl-config'));base.EXACT_IMAGES={ref:ident.removeprefix('sha256:') for ref,ident in ids.items()}
    env={k:v for k,v in os.environ.items() if not k.upper().startswith(('COMPOSE_','AD_'))}
    env.update(ACADEMIC_STATE=str(STATE),AD_BIND_PORT=str(PORT),AD_PORTAL_HOST=PORTAL_HOST,AD_EXTERNAL_PORT=str(PORT),
               AD_INGRESS_IP=PROXY_IP,AD_CORE_SUBNET=SUBNET,AD_FRONTEND_IMAGE=FRONTEND,
               AD_RC_PROJECT=PROJECT,AD_RC_KC=images['keycloak'],AD_RC_BACKEND=images['backend'],AD_RC_RISK=images['risk'],AD_RC_GATEWAY=images['gateway'])
    cmd=['docker','compose','-p',PROJECT,'--project-directory',str(rc.linux.LOCAL)]
    for f in (rc.linux.LOCAL/'compose.academic-demo.yaml',ROOT/'deploy/academic-linux/compose.production-demo.yaml',ROOT/'deploy/academic-linux/rc/compose.rc.yaml',HERE/'compose.full-function.yaml'):
        cmd+=['-f',str(f)]
    def compose(*args,check=True,data=None,timeout=420):
        p=subprocess.run([*cmd,*args],env=env,input=data,capture_output=True,encoding='utf-8',timeout=timeout,cwd=ROOT)
        if check and p.returncode:
            safe=sorted(set(re.findall(r'\b(?:[A-Za-z]+Exception|PKIX|UNREVIEWED_MYSQL_VERSION|V5_[A-Z0-9_]+)\b',p.stdout+p.stderr)))
            raise RuntimeError('Full-function Compose '+args[0]+' failed; '+str(safe)+'; secret output withheld')
        if args == ('run','--rm','--no-deps','materialize') and p.returncode == 0:
            # Migrator JVMs validate revocation before opening a database connection.
            compose('up','-d','--wait','--wait-timeout','60','crl')
        return p
    base.compose=compose
    check(STATE.resolve()==STATE and STATE.parent.resolve()==STATE.parent,'Unexpected state path')
    names=run('docker','network','ls','--format','{{.Name}}').stdout.splitlines()
    for name in names:
        network=json.loads(run('docker','network','inspect','--format','{{json .}}',name).stdout)
        if name.startswith(PROJECT+'_'):
            check((network.get('Labels') or {}).get('com.docker.compose.project')==PROJECT,'Foreign network ownership')
        else:
            for block in (network.get('IPAM') or {}).get('Config') or []:
                if block.get('Subnet'):
                    n=ipaddress.ip_network(block['Subnet'],strict=False)
                    check(n.version!=4 or not n.overlaps(base.SUBNET),'New profile subnet overlaps another project')
    owned_ids=run('docker','ps','-aq','--filter','label=com.docker.compose.project='+PROJECT).stdout.splitlines()
    for ident in owned_ids:
        item=json.loads(run('docker','inspect',ident).stdout)[0]
        check(item['Config']['Labels'].get('io.zerotrust.scope')==PROJECT,'Foreign container label')
        for mount in item['Mounts']:
            if mount['Type']=='volume':check(mount['Name'] in {PROJECT+'_'+x for x in base.VOLUMES},'Foreign volume mount')
            else:check(item['Config']['Labels']['com.docker.compose.service']=='materialize' and not mount['RW'],'Unexpected bind mount')
    model=json.loads(compose('--profile','*','config','--format','json').stdout)
    check(all(s['labels']['io.zerotrust.scope']==PROJECT for s in model['services'].values()),'Foreign ownership')
    check(all(not v.get('external') and v['name'].startswith(PROJECT+'_') for group in ('volumes','networks') for v in model[group].values()),'Foreign network/volume')
    check(model['networks']['core']['internal'] and model['networks']['recovery']['internal'],'Internal network required')
    check(set(model['volumes'])==base.VOLUMES,'Unexpected volume set')
    check(all(not s.get('ports') for n,s in model['services'].items() if n not in ('ingress','crl')),'Private service published')
    check(all(p['host_ip']=='127.0.0.1' for n in ('ingress','crl') for p in model['services'][n]['ports']),'Non-loopback listener')
    for name,port in (('ingress',PORT),('crl',39445)):
        check(len(model['services'][name]['ports'])==1 and
              int(model['services'][name]['ports'][0]['published'])==port and
              int(model['services'][name]['ports'][0]['target'])==port,'Unexpected listener port')
    for name,service in model['services'].items():
        for mount in service.get('volumes',[]):
            if mount['type']=='bind':
                check(name=='materialize' and mount.get('read_only') and
                      Path(mount['source']).resolve() in (STATE.resolve(),(HERE/'materialize.sh').resolve()),'Foreign state/script bind rejected')
    receipt=OUT/'profile-images.json'
    doc={'kind':'ISOLATED_SYNTHETIC_FULL_FUNCTION_NOT_RELEASE_LOCK','realm':'DoAn','images':ids,'frontend_mode':'standard','D17':'PENDING','G8':'INTERNET_NO_GO'}
    if receipt.exists():check(json.loads(receipt.read_text())==doc,'Image receipt drift')
    else:receipt.write_text(json.dumps(doc,indent=2)+'\n')
    return c,compose


def install(c, compose, resume):
    if resume:
        check((STATE/'owner').read_text()==PROJECT and not (STATE/'installed').exists(),'Not an incomplete owned installation')
        for service in ('backend','risk','frontend'):
            check(not run('docker','ps','-q','--filter','label=com.docker.compose.project='+PROJECT,
                          '--filter','label=com.docker.compose.service='+service).stdout.strip(),'Application writers already running; inspect instead of reseeding')
    else:
        rc.fresh(c,PROJECT)
        prepare()
    compose('run','--rm','--no-deps','materialize')
    try:
        compose('up','-d','--wait','--wait-timeout','150','mysql80')
        check(rc.sql('mysql80','SELECT VERSION()')=='8.0.46','Bootstrap version drift')
        compose('run','--rm','--no-deps','migrate80')
        expected=rc.ledger('mysql80','pd_staging_')
        expected_schema=rc.schema('mysql80','pd_staging_')
        check([line.split('\t')[0] for line in expected.splitlines()]==list('12345') and
              rc.sql('mysql80',rc.V5)=='661092940\t1','V1-V5/checksum mismatch')
        dump=compose('exec','-T','mysql80','mysqldump','--defaults-extra-file=/fixture/root.cnf',
                     '--single-transaction','--set-gtid-purged=OFF','--no-tablespaces','--skip-add-drop-table','pd_staging_risk').stdout
    finally:compose('stop','--timeout','45','mysql80')
    compose('up','-d','--wait','--wait-timeout','150','mysql','redis')
    check(rc.sql('mysql','SELECT VERSION()')=='8.4.13','Runtime version drift')
    if not rc.schema('mysql','pd_staging_'):
        compose('exec','-T','mysql','mysql','--defaults-extra-file=/fixture/root.cnf','pd_staging_risk',data=dump)
    check(rc.schema('mysql','pd_staging_')==expected_schema and rc.ledger('mysql','pd_staging_')==expected,'Schema transfer mismatch')
    print('PASS isolated TLS, V1-V5 checksum 661092940 and 8.0.46 to 8.4.13 schema transfer',flush=True)
    if rc.sql('mysql',"SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='pd_staging_keycloak' AND TABLE_NAME='REALM'")=='0':
        compose('up','-d','--wait','--wait-timeout','380','keycloak-init')
        compose('stop','--timeout','60','keycloak-init')
    check(rc.sql('mysql',"SELECT COUNT(*) FROM pd_staging_keycloak.REALM WHERE NAME='DoAn'")=='1','Fresh DoAn realm missing')
    compose('up','-d','--wait','--wait-timeout','220',*rc.HEALTHY,'crl')
    base.save('.','installed',rc.linux.digest(OUT/'profile-images.json'))
    print('PASS isolated full-function stack installed; no protected state used',flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('validate','install','resume','complete-startup','status','restart','test','test-mfa','test-risk','test-persistence','test-failclosed','stop'))
    action=parser.parse_args().action
    c,compose=configure()
    if action=='validate':print('PASS isolated ownership, exact images, private networks and loopback ports')
    elif action in ('install','resume'):install(c,compose,action=='resume')
    elif action=='complete-startup':
        check((STATE/'owner').read_text()==PROJECT and not (STATE/'installed').exists(),'Only an incomplete owned startup may be completed')
        compose('stop','--timeout','45','ingress','gateway','backend','risk','keycloak','frontend')
        compose('run','--rm','--no-deps','materialize')
        compose('up','-d','--wait','--wait-timeout','220',*rc.HEALTHY,'crl')
        base.save('.','installed',rc.linux.digest(OUT/'profile-images.json'))
        print('PASS completed owned startup without reimport, migration or account reset',flush=True)
    elif action=='status':
        payload=compose('ps','--format','json').stdout
        try:
            parsed=json.loads(payload);rows=parsed if isinstance(parsed,list) else [parsed]
        except json.JSONDecodeError:rows=[json.loads(x) for x in payload.splitlines() if x]
        print(json.dumps([{k:x.get(k) for k in ('Service','State','Health')} for x in rows]))
    elif action=='restart':
        check((STATE/'installed').is_file(),'Profile not installed')
        compose('restart',*rc.HEALTHY,'crl')
        compose('up','-d','--wait','--wait-timeout','180',*rc.HEALTHY,'crl')
    elif action.startswith('test'):
        check((STATE/'installed').is_file(),'Profile not installed')
        results=OUT/'results';results.mkdir(exist_ok=True)
        network_ip=['--ip',HIGH_TEST_IP] if action=='test-risk' else []
        script={'test':'verify.py','test-mfa':'verify_mfa.py','test-risk':'verify_risk.py',
                'test-persistence':'verify_persistence.py','test-failclosed':'verify_persistence.py'}[action]
        if action=='test-failclosed':compose('stop','--timeout','30','risk')
        try:
            result=run('docker','run','--rm','--name',PROJECT+'-browser-check','--label','io.zerotrust.scope='+PROJECT,
                   '--network',PROJECT+'_core','--cap-drop','ALL','--security-opt','no-new-privileges',
                   '--shm-size','256m','--memory','1g',*network_ip,
                   '--mount',f'type=bind,source={STATE},target=/private,readonly',
                   '--mount',f'type=bind,source={HERE},target=/tests,readonly',
                   '--mount',f'type=bind,source={results},target=/results',
                   'zt-full-function/browser:20261111-1','/tests/'+script,
                   *(['--risk-down'] if action=='test-failclosed' else []),timeout=600,check=False)
        finally:
            if action=='test-failclosed':compose('up','-d','--wait','--wait-timeout','100','risk')
        text='\n'.join(line for line in result.stdout.splitlines() if line.startswith(('PASS ','FAIL ')))+'\n'
        (OUT/('acceptance.log' if action=='test' else action+'-acceptance.log')).write_text(text)
        print(text,end='',flush=True)
        check(result.returncode==0,'Targeted acceptance failed; see sanitized results')
    else:compose('stop','--timeout','45',*rc.HEALTHY,'crl')


if __name__=='__main__':main()
