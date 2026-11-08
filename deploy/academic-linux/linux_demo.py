"""Build, validate and operate the isolated Academic Demo Linux profile."""
import argparse
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import serialization

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LOCAL = ROOT/'deploy/academic-demo'
sys.path.insert(0,str(LOCAL))
import academic_demo as base

PROJECT = 'zt-academic-linux'
SCOPE = 'academic-demo-linux'
NODE = 'node:24.22.2-alpine@sha256:ec318aabf188af4e5488847eea4b24452650b9917140563e140762526a37f1df'
APP_IMAGES = dict(base.EXACT_IMAGES)
IMAGE_PINS = {
    **{ref:'sha256:'+digest for ref,digest in APP_IMAGES.items()},
    'mysql:8.0.46@sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b':'sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b',
    'redis@sha256:ec1c2d3603c3d7d65b153bedda0248b641aa3bd7684503406b27b9e870ac0796':'sha256:ec1c2d3603c3d7d65b153bedda0248b641aa3bd7684503406b27b9e870ac0796',
    'nginx:1.30.6-alpine@sha256:bb8f722b4be005fcd7827816a136ab779fd40185d85b5171be915cc7fc0575c7':'sha256:bb8f722b4be005fcd7827816a136ab779fd40185d85b5171be915cc7fc0575c7',
}
HEALTHY = ('ingress','gateway','frontend','backend','risk','keycloak','redis','mysql')
EXPECTED = {'mode','release','portal_host','auth_host','external_port','bind_port','core_subnet','state_dir','certificate','private_key','edge_ca'}


def check(valid, message):
    if not valid:
        raise RuntimeError(message)


def host_name(value):
    return isinstance(value,str) and '.' in value and len(value)<=253 and all(
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in value.split('.'))


def load_config(path):
    c=json.loads(path.read_text(encoding='utf-8'))
    check(set(c)==EXPECTED and c['mode'] in ('rehearsal','production-demo'),'Invalid configuration fields')
    check(re.fullmatch(r'[a-z0-9][a-z0-9._-]{1,62}',c['release']),'Invalid immutable release label')
    hosts=(c['portal_host'],c['auth_host'])
    check(len(set(hosts))==2 and all(host_name(h) for h in hosts),'Distinct DNS hostnames required')
    for key in ('external_port','bind_port'):
        check(type(c[key]) is int and 1<=c[key]<=65535,'Invalid HTTPS port')
    check(1024<=c['bind_port']<=65535 and c['bind_port']!=19443,'Use a separate high loopback port')
    rehearsal=c['mode']=='rehearsal'
    if rehearsal:
        check(all(h.endswith('.test') for h in hosts) and c['external_port']==c['bind_port']
              and not any(c[key] for key in ('certificate','private_key','edge_ca')),'Invalid isolated rehearsal inputs')
    else:
        check(c['external_port']==443 and all(not h.endswith(('.test','.invalid','.localhost')) for h in hosts),
              'Production-demo requires external DNS and HTTPS port 443')
        check(all(isinstance(c[key],str) and Path(c[key]).is_absolute() for key in ('certificate','private_key','edge_ca')),
              'Provide absolute PKI file paths')
    n=ipaddress.ip_network(c['core_subnet'])
    check(n.version==4 and n.is_private and 24<=n.prefixlen<=28,'Private IPv4 subnet /24–/28 required')
    state=Path(c['state_dir'])
    check(state.is_absolute() and state.resolve()==state and not state.is_relative_to(ROOT)
          and state.name.startswith(('zerotrust-','academic-linux')),'Dedicated state path outside the repository required')
    for key in ('portal','auth'):
        c[key+'_url']='https://'+c[key+'_host']+('' if c['external_port']==443 else f":{c['external_port']}")
    c['state']=state
    c['network']=n
    c['proxy_ip']=str(n.network_address+9)
    c['frontend_image']='zt-academic-linux/frontend:'+c['release']
    c['schema_env']='staging' if rehearsal else 'production'
    return c


def run(*args, check_result=True, data=None, timeout=300, env=None):
    p=subprocess.run(args, input=data, capture_output=True, encoding='utf-8', errors='replace',
                     timeout=timeout, env=env, cwd=ROOT)
    if check_result:
        check(p.returncode==0,f'{args[0]} {args[1]} failed ({p.returncode})')
    return p


def activate(c):
    # Reuse the reviewed PD-R19 helpers in this process with a separate Compose project.
    base.PROJECT=PROJECT
    base.SCOPE=SCOPE
    base.STATE=c['state']
    base.SUBNET=c['network']
    base.PORT=c['bind_port']
    base.PORTAL_HOST=c['portal_host']
    base.AUTH_HOST=c['auth_host']
    base.PORTAL=c['portal_url']
    base.AUTH=c['auth_url']
    base.ISSUER=base.AUTH+'/realms/'+base.REALM
    # Runtime connections stay in the private network. Tokens still carry the external issuer.
    internal='https://keycloak:8443/realms/'+base.REALM+'/protocol/openid-connect/'
    base.JWK=internal+'certs'
    base.TOKEN=internal+'token'

    def compose(*args, check=True, data=None, timeout=420):
        env={k:v for k,v in os.environ.items() if not k.upper().startswith(('COMPOSE_','AD_'))}
        env.update(ACADEMIC_STATE=str(c['state']),AD_BIND_PORT=str(c['bind_port']),
            AD_PORTAL_HOST=c['portal_host'],AD_EXTERNAL_PORT=str(c['external_port']),
            AD_INGRESS_IP=c['proxy_ip'],AD_CORE_SUBNET=c['core_subnet'],AD_FRONTEND_IMAGE=c['frontend_image'])
        return run('docker','compose','-p',PROJECT,'--project-directory',str(LOCAL),
            '-f',str(LOCAL/'compose.academic-demo.yaml'),'-f',str(HERE/'compose.production-demo.yaml'),
            *args,check_result=check,data=data,timeout=timeout,env=env)
    base.compose=compose


def compose_contract(c):
    model=json.loads(base.compose('--profile','*','config','--format','json').stdout)
    services=model['services']
    check(set(services)==set(HEALTHY)|{'keycloak-init','migrate','materialize','mysql-restore'},'Unexpected service set')
    check(all(s['labels']['io.zerotrust.scope']==SCOPE for s in services.values()),'Wrong project labels')
    check(set(services['ingress']['networks'])=={'core','edge'}
          and all('edge' not in s.get('networks',{}) for name,s in services.items() if name!='ingress'),'Unexpected edge service')
    check(all(set(services[n]['networks'])=={'core'} for n in ('mysql','redis','risk','keycloak')),'Private service network mismatch')
    check(all(not services[n].get('ports') for n in services if n!='ingress'),'Unexpected published port')
    ports=services['ingress']['ports']
    check(len(ports)==1 and ports[0]['host_ip']=='127.0.0.1' and int(ports[0]['published'])==c['bind_port']
          and int(ports[0]['target'])==8443,'Loopback ingress mismatch')
    check(model['networks']['core']['internal'] and model['networks']['recovery']['internal'],'Private networks required')
    check(all(not x.get('external') for x in model['volumes'].values()),'External volumes rejected')
    binds=[(n,m) for n,s in services.items() for m in s.get('volumes',[]) if m['type']=='bind']
    check(len(binds)==2 and all(n=='materialize' and m.get('read_only') for n,m in binds)
          and {Path(m['source']).resolve() for n,m in binds}=={c['state'],LOCAL/'materialize.sh'},'Unexpected host mount')
    return model


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def deployment_inputs():
    files={'database/schema.sql','deploy/demo/fixtures.py','deploy/docker/Dockerfile.frontend',
          'deploy/public-demo/render_ingress.py','deploy/public-demo/ingress-contract.json','deploy/public-demo/redis-acl-contract.conf'}
    files|={p.relative_to(ROOT).as_posix() for p in LOCAL.iterdir() if p.is_file() and p.suffix!='.md'}
    files|={(HERE/name).relative_to(ROOT).as_posix() for name in ('linux_demo.py','compose.production-demo.yaml')}
    return files


def source_snapshot():
    paths=run('git','-c','core.quotepath=false','ls-files','--cached','--others','--exclude-standard','--','frontend').stdout.splitlines()
    files=set(paths)|deployment_inputs()
    return {name:digest(ROOT/name) for name in sorted(files)}


def image_id(ref):
    p=run('docker','image','inspect','--format','{{.Id}} {{.Os}}/{{.Architecture}}',ref,check_result=False)
    if p.returncode:
        return None
    ident,arch=p.stdout.split()
    check(arch=='linux/amd64','Image platform mismatch')
    return ident


def lock(c, path):
    check(not path.exists(),'Manifest already exists; use a fresh release label')
    check(not any(os.getenv(k) for k in ('DOCKER_HOST','DOCKER_CONTEXT')),'Remote Docker override rejected')
    base.verify_boundary()
    compose_contract(c)
    for ref,expected in IMAGE_PINS.items():
        if image_id(ref) is None and ref not in APP_IMAGES:
            run('docker','pull','--platform','linux/amd64',ref,timeout=600)
        check(image_id(ref)==expected,'Baseline image ID mismatch')
    revision=run('git','rev-parse','HEAD').stdout.strip()
    files=source_snapshot()
    snapshot=hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest()
    check(image_id(c['frontend_image']) is None,'Frontend tag already exists; use a fresh release label')
    args={'NODE_IMAGE':NODE,'KEYCLOAK_URL':c['auth_url'],'KEYCLOAK_REALM':base.REALM,'KEYCLOAK_CLIENT_ID':'zerotrust-spa',
          'API_BASE_URL':'','PORTAL_MODE':'public-demo','SITE_URL':c['portal_url'],'RUN_CHECKS':'true',
          'SOURCE_REVISION':revision,'SOURCE_SNAPSHOT':snapshot}
    cmd=['docker','buildx','build','--platform','linux/amd64','--load','-f','deploy/docker/Dockerfile.frontend','-t',c['frontend_image']]
    for k,v in args.items():
        cmd+=['--build-arg',f'{k}={v}']
    subprocess.run([*cmd,'.'],cwd=ROOT,check=True)
    check(source_snapshot()==files,'Source changed during frontend build')
    manifest={'release':c['release'],'mode':c['mode'],'platform':'linux/amd64','revision':revision,
        'source_hashes':files,'frontend_build_args':args,
        'images':{**IMAGE_PINS,c['frontend_image']:image_id(c['frontend_image'])}}
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x',encoding='utf-8') as f:
        json.dump(manifest,f,indent=2,sort_keys=True)
        f.write('\n')
    print('Release lock generated for eight exact runtime images.')


def read_lock(c,path):
    data=json.loads(path.read_text(encoding='utf-8'))
    check(data['release']==c['release'] and data['mode']==c['mode'] and data['platform']=='linux/amd64'
          and data['frontend_build_args']['SITE_URL']==c['portal_url']
          and data['frontend_build_args']['KEYCLOAK_URL']==c['auth_url'],'Release lock does not match target')
    check(set(data['images'])==set(IMAGE_PINS)|{c['frontend_image']}
          and all(data['images'][ref]==v for ref,v in IMAGE_PINS.items()),'Unexpected release image set')
    for ref,expected in data['images'].items():
        check(image_id(ref)==expected and expected,'Loaded image does not match release lock')
    files=data['source_hashes']
    if (ROOT/'.git').exists():
        check(source_snapshot()==files,'Deployment source does not match lock')
    else:
        check(deployment_inputs()<=set(files),'Deployment inputs missing from lock')
        for name,expected in files.items():
            p=ROOT/name
            check(p.resolve()==p and p.is_relative_to(ROOT) and p.is_file() and digest(p)==expected,
                  'Transfer bundle source does not match lock')
    return data


def load_pki(c):
    if c['mode']=='rehearsal':
        return None
    cert,key,ca=[Path(c[k]) for k in ('certificate','private_key','edge_ca')]
    check(all(x.is_file() for x in (cert,key,ca)) and key.resolve()==key and key.stat().st_mode&0o077==0,
          'TLS key requires protected non-symlink file')
    chain=x509.load_pem_x509_certificates(cert.read_bytes())
    private=serialization.load_pem_private_key(key.read_bytes(),password=None)
    public=lambda k:k.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    check(public(chain[0].public_key())==public(private.public_key()),'TLS certificate/key mismatch')
    with tempfile.TemporaryDirectory(prefix='zt-edge-verify-') as td:
        leaf=Path(td)/'leaf.pem'
        leaf.write_bytes(chain[0].public_bytes(serialization.Encoding.PEM))
        for host in (c['portal_host'],c['auth_host']):
            p=run('openssl','verify','-purpose','sslserver','-CAfile',str(ca),'-untrusted',str(cert),
                  '-verify_hostname',host,str(leaf),check_result=False)
            check(p.returncode==0,'TLS chain/SAN validation failed')
    return (cert.read_bytes(),key.read_bytes(),ca.read_bytes())


@contextmanager
def scoped_keytool(state):
    if shutil.which('keytool'):
        yield
        return
    # The isolated helper writes only a synthetic CA truststore to the new state directory.
    with tempfile.TemporaryDirectory(prefix='zt-keytool-') as td:
        shim=Path(td)/'keytool'
        shim.write_text('''#!/bin/sh
set -eu
exec docker run --rm --network none --cap-drop ALL --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$AD_KEYTOOL_STATE,target=/private" --entrypoint keytool \
  zt-pd02-candidate/portal:pd-r11-c401e17 -importcert -noprompt -alias academic-ca \
  -file /private/ca.crt -storetype PKCS12 -keystore /private/trust.p12 -storepass:file /private/trust-password
''')
        shim.chmod(0o700)
        path=os.environ['PATH']
        try:
            os.environ['PATH']=td+os.pathsep+path
            os.environ['AD_KEYTOOL_STATE']=str(state)
            yield
        finally:
            os.environ['PATH']=path
            os.environ.pop('AD_KEYTOOL_STATE',None)


def state_identity(c):
    fields=('mode','portal_host','auth_host','external_port','bind_port','core_subnet','schema_env')
    return {k:c[k] for k in fields}


def prepare(c,pki):
    state=c['state']
    if state.exists():
        marker=state/'linux-profile'
        check(state.stat().st_mode&0o077==0 and state.stat().st_uid==os.getuid() and marker.is_file(),
              'Private state belongs to another profile or is incomplete')
        recorded=json.loads(marker.read_text())
        recorded.pop('release',None)
        check(recorded==state_identity(c),
              'Private state belongs to another profile or is incomplete')
        if pki:
            check(all((state/'ingress'/name).read_bytes()==value
                      for name,value in zip(('server.crt','server.key','edge-ca.crt'),pki)),
                  'TLS material changed; use reviewed certificate rotation procedure')
        return
    state.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.zt-bootstrap-',dir=state.parent) as td:
        scratch=Path(td)/'private'
        base.STATE=scratch
        try:
            with scoped_keytool(scratch):
                base.prepare()
            for role in ('installer','keycloak'):
                p=scratch/role/'keycloak.conf'
                s=re.sub(r'(?m)^https-port=\d+$','https-port=8443',p.read_text())
                s=s.replace('172.31.230.9/32',c['proxy_ip']+'/32')
                # Realm import and subsequent runtime do not require a master admin user.
                s='\n'.join(x for x in s.splitlines() if not x.startswith('bootstrap-admin-'))+'\n'
                base.save(role,'keycloak.conf',s)
            backend=scratch/'backend/application.properties'
            base.save('backend',backend.name,backend.read_text().replace('keycloak.admin.server-url='+base.AUTH,
                                                                      'keycloak.admin.server-url=https://keycloak:8443'))
            gateway=scratch/'gateway/application.properties'
            base.save('gateway',gateway.name,gateway.read_text().replace('172.31.230.9/32',c['proxy_ip']+'/32'))
            if c['schema_env']=='production':
                files=[('mysql','init.sql'),('mysql','school.cnf'),('migrate','migration.properties'),
                    ('backend','application.properties'),('risk','application.properties'),('gateway','application.properties'),
                    ('installer','keycloak.conf'),('keycloak','keycloak.conf')]
                for role,name in files:
                    s=(scratch/role/name).read_text().replace('pd_staging_','pd_production_')
                    s=s.replace('app.public-demo.environment=staging','app.public-demo.environment=production')
                    if role=='risk':
                        s='\n'.join(line for line in s.splitlines() if not line.startswith(('risk.policy.network-risk.trusted-cidrs=',
                            'risk.policy.network-risk.high-risk-cidrs=','risk.policy.priority-rules.blocked-ip-addresses=')))+'\n'
                    base.save(role,name,s)
            ingress=base.load(ROOT/'deploy/public-demo/ingress-contract.json')
            ingress.update(listen_port=8443,portal_host=c['portal_host'],auth_host=c['auth_host'],realm=base.REALM,
                certificate='/run/demo/server.crt',certificate_key='/run/demo/server.key',upstream_ca='/run/demo/ca.crt',
                gateway={'url':'https://gateway:8443','tls_name':'gateway'},
                keycloak={'url':'https://keycloak:8443','tls_name':'keycloak'})
            nginx=base.render(ingress).replace('pid logs/nginx.pid;','pid /tmp/nginx.pid;').replace('error_log logs/error.log crit;','error_log stderr crit;')
            nginx=nginx.replace('X-Forwarded-Port 443;',f"X-Forwarded-Port {c['external_port']};")
            base.save('ingress','nginx.conf',nginx)
            if pki:
                for name,data in zip(('server.crt','server.key','edge-ca.crt'),pki):
                    base.save('ingress',name,data)
            else:
                base.save('ingress','edge-ca.crt',(scratch/'ca.crt').read_bytes())
            base.save('.','linux-profile',json.dumps(state_identity(c),sort_keys=True))
            scratch.rename(state)
        finally:
            base.STATE=state


def sql(service, query, profile='root'):
    return base.compose('exec','-T',service,'mysql',f'--defaults-extra-file=/fixture/{profile}.cnf','-Nse',query).stdout.strip()


def start(c):
    state=c['state']
    if not state.exists():
        resources=run('docker','volume','ls','-q','--filter',f'label=com.docker.compose.project={PROJECT}').stdout
        check(not resources.strip(),'Existing Academic Demo volumes require their original state directory')
    prepare(c,load_pki(c))
    prefix='pd_'+c['schema_env']+'_'
    if not (state/'installed').is_file():
        base.compose('run','--rm','--no-deps','materialize')
        base.compose('up','-d','--wait','--wait-timeout','150','mysql','redis')
        check(sql('mysql',f"SELECT COUNT(*) FROM performance_schema.threads WHERE PROCESSLIST_USER='{prefix}risk_runtime'")=='0',
              'Risk runtime writers active before Flyway')
        base.compose('run','--rm','--no-deps','migrate')
        check(sql('mysql',f"SELECT checksum,success FROM {prefix}risk.flyway_schema_history WHERE version='5'")=='661092940\t1',
              'Flyway V5 ledger mismatch')
        base.compose('up','-d','--wait','--wait-timeout','165','keycloak-init')
        base.compose('stop','--timeout','60','keycloak-init')
        exitcode=run('docker','inspect','--format','{{.State.ExitCode}}',PROJECT+'-keycloak-init-1').stdout.strip()
        check(exitcode in ('0','143'),'Keycloak installer did not stop gracefully')
        check(sql('mysql',f"SELECT COUNT(*) FROM {prefix}keycloak.REALM WHERE NAME='{base.REALM}'")=='1','Synthetic realm missing')
        base.save('.','installed',SCOPE)
        print('V5 661092940 and synthetic realm installed. Keycloak installer stopped gracefully.')
    base.compose('up','-d','--wait','--wait-timeout','200')
    print('Eight Linux services reached health checks. HTTPS remains loopback-only.')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--manifest',type=Path)
    parser.add_argument('action',choices=('validate','lock','start','status','stop'))
    a=parser.parse_args()
    check(platform.system()=='Linux' and platform.machine()=='x86_64','Linux amd64 required')
    c=load_config(a.config)
    activate(c)
    compose_contract(c)
    if a.action=='validate':
        print('Compose topology and external hostname/port inputs validated. No traffic opened.')
        return
    check(a.manifest is not None,'An explicit manifest path is required')
    if a.action=='lock':
        lock(c,a.manifest)
        return
    base.verify_boundary()
    read_lock(c,a.manifest)
    if a.action=='start':
        start(c)
    elif a.action=='stop':
        marker=c['state']/'linux-profile'
        check(marker.is_file(),'Stop requires the original Academic Demo state directory')
        recorded=json.loads(marker.read_text())
        recorded.pop('release',None)
        check(recorded==state_identity(c),'Stop profile does not match installed state')
        base.compose('stop','--timeout','45',*HEALTHY)
    else:
        print(base.compose('ps','-a').stdout,end='')


if __name__=='__main__':
    try:
        main()
    except (RuntimeError,ValueError,OSError,subprocess.SubprocessError,KeyError) as error:
        detail=str(error) if type(error) is RuntimeError else type(error).__name__
        raise SystemExit('Linux deployment stopped: '+detail) from None
