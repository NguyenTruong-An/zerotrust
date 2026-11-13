"""One consistent encrypted synthetic checkpoint; restore ONLY into new volumes.

Source is the owned full-function candidate. Protected Lab/PD-R19 are never targets.
No image build, migration replay, release promotion or external ports.
"""
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import socket
import ssl
import tarfile
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import operate as full

PROJECT='zt-full-function-phase2-restore'
WRITERS=('gateway','backend','risk','keycloak','frontend')
ROOTS={'mysql','redis','keycloak','installer','backend','risk','gateway','migrate','ingress','crl'}


def public_witness():
    ctx=ssl.create_default_context(cafile=str(full.STATE/'ca-with-crl.pem'))
    ctx.verify_flags|=ssl.VERIFY_CRL_CHECK_CHAIN
    conn=http.client.HTTPSConnection(full.AUTH_HOST,full.PORT,context=ctx,timeout=15)
    conn.sock=ctx.wrap_socket(socket.create_connection(('127.0.0.1',full.PORT),timeout=15),server_hostname=full.AUTH_HOST)
    conn.request('GET','/realms/DoAn/protocol/openid-connect/certs');response=conn.getresponse()
    full.check(response.status==200,'Source normal TLS/CRL JWKS read failed')
    jwks=json.loads(response.read());conn.close()
    # JWKS is an unordered key set. Match exact public key/certificate content
    # by kid, rather than the incidental serialization order of its array.
    return {'jwks_by_kid_sha256':{k['kid']:hashlib.sha256(json.dumps(k,sort_keys=True).encode()).hexdigest() for k in jwks['keys']}}


def complete(source,dest,work,state):
    witness={}
    for table,order in (('school.users','id'),('school.students','id'),('school.scores','id'),('keycloak.REALM','ID'),
                        ('keycloak.USER_ENTITY','ID'),('keycloak.CREDENTIAL','ID'),('keycloak.COMPONENT','ID'),
                        ('keycloak.COMPONENT_CONFIG','ID'),('keycloak.AUTHENTICATION_FLOW','ID'),
                        ('keycloak.AUTHENTICATION_EXECUTION','ID'),('risk.subject_device_trust','subject_id'),
                        ('risk.known_devices','id'),('risk.device_trust_revocations','operation_id'),
                        ('risk.authentication_success_events','id'),('risk.flyway_schema_history','installed_rank')):
        query='SELECT * FROM pd_staging_'+table+' ORDER BY '+order
        before=source('exec','-T','mysql','mysql','--defaults-extra-file=/fixture/root.cnf','--binary-as-hex','-Nse',query).stdout.encode()
        after=dest('exec','-T','mysql','mysql','--defaults-extra-file=/fixture/root.cnf','--binary-as-hex','-Nse',query).stdout
        full.check(before.replace(b'\r\n',b'\n')==after.replace(b'\r\n',b'\n'),'Restored critical table differs: '+table)
        witness[table]=hashlib.sha256(after).hexdigest()
    encrypted=(work/'redis.aesgcm').read_bytes();key=(state/'backup.key').read_bytes()
    original=AESGCM(key).decrypt(encrypted[:12],encrypted[12:],b'redis')
    config=json.loads((work/'compose.restore.json').read_text())
    restored=subprocess.run(['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--user','999:999',
        '--mount',f'type=volume,source={PROJECT}_redis-data,target=/data,readonly','--entrypoint','tar',
        config['services']['redis']['image'],'-C','/data','-cf','-','.'],capture_output=True,check=True,timeout=90).stdout
    def files(data):
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            return {m.name:hashlib.sha256(archive.extractfile(m).read()).hexdigest() for m in archive.getmembers() if m.isfile()}
    full.check(files(original)==files(restored),'Restored Redis AOF files differ')
    (work/'state-witness.json').write_text(json.dumps({'tables_sha256':witness,'redis_files_sha256':files(restored),'original_state_used':False},indent=2)+'\n')
    print('PASS exact restored School, credentials, signing-key components, Browser Flow, Risk generations/devices/events, Redis AOF and V5',flush=True)
    verify_restored_login(dest,work,state)


def verify_restored_login(dest,work,state):
    dest('up','-d','--wait','--wait-timeout','240',*full.rc.HEALTHY,'crl',timeout=360)
    p=subprocess.run(['docker','run','--rm','--name',PROJECT+'-check','--network',PROJECT+'_core','--cap-drop','ALL',
        '--security-opt','no-new-privileges','--memory','1g','--shm-size','256m',
        '--mount',f'type=bind,source={state},target=/private,readonly','--mount',f'type=bind,source={full.HERE},target=/tests,readonly',
        '--mount',f'type=bind,source={work},target=/results','zt-full-function/browser:20261111-1','/tests/phase2_verify_restore.py'],
        capture_output=True,text=True,encoding='utf-8',timeout=180)
    safe='\n'.join(x for x in p.stdout.splitlines() if x.startswith(('PASS ','FAIL ')))+'\n';print(safe,end='',flush=True)
    (work/'browser.log').write_text(safe);full.check(p.returncode==0,'Post-restore targeted authentication failed')


def restore_source(source):
    source('up','-d','--wait','--wait-timeout','180',*(x for x in full.rc.HEALTHY if x!='ingress'),'crl')
    # stop/start can reallocate upstream container IPs. Refresh this project's
    # static NGINX resolution only after its upstreams are healthy again.
    source('restart','ingress')
    source('up','-d','--wait','--wait-timeout','100',*full.rc.HEALTHY,'crl')
    print('PASS active full-function candidate restored healthy; disposable restore retained stopped',flush=True)


def resume(auth_only=False):
    _,source=full.configure();work=full.OUT/'phase2'/'restore';state=work/'private'
    full.check((state/'owner').read_text()==PROJECT and (state/'backup.key').is_file(),'Owned checkpoint required')
    config=work/'compose.restore.json';model=json.loads(config.read_text())
    full.check(model['name']==PROJECT and all(not s.get('ports') for s in model['services'].values()),'Invalid private restore scope')
    for g in ('networks','volumes'):
        full.check(all(not v.get('external') and v['name'].startswith(PROJECT+'_') for v in model[g].values()),'Foreign restore resource')
    ids=full.run('docker','ps','-aq','--filter','label=com.docker.compose.project='+PROJECT).stdout.split()
    for x in json.loads(full.run('docker','inspect',*ids).stdout):
        full.check(x['Config']['Labels'].get('io.zerotrust.scope')==PROJECT,'Restore ownership mismatch')
        full.check(not x['HostConfig']['PortBindings'],'Unexpected restore port binding')
        full.check(all(m['Type']=='volume' and m['Name'].startswith(PROJECT+'_') for m in x['Mounts']),'Foreign restore mount')
    def dest(*args,data=None,timeout=240):
        p=subprocess.run(['docker','compose','-p',PROJECT,'--project-directory',str(full.ROOT),'-f',str(config),*args],input=data,capture_output=True,timeout=timeout,cwd=full.ROOT)
        full.check(p.returncode==0,'Disposable restore failed: '+args[0]+'; secret output withheld');return p
    if auth_only:(state/'phase2-restore-public-witness.json').write_text(json.dumps(public_witness())+'\n')
    try:
        source('stop','--timeout','45',*WRITERS,'redis')
        dest('up','-d','--wait','--wait-timeout','160','mysql','crl')
        if auth_only:
            full.check((work/'state-witness.json').is_file(),'Completed data witness required before authentication-only continuation')
            verify_restored_login(dest,work,state)
        else:complete(source,dest,work,state)
    finally:
        try:dest('stop','--timeout','45',*full.rc.HEALTHY,'crl')
        finally:restore_source(source)


def main():
    _,source=full.configure()
    work=full.OUT/'phase2'/'restore';state=work/'private'
    full.check(not work.exists(),'Restore destination exists; inspect retained evidence rather than overwrite it')
    for kind in ('container','network','volume'):
        if kind=='container':names=full.run('docker','ps','-a','--format','{{.Names}}').stdout.splitlines()
        else:names=full.run('docker',kind,'ls','--format','{{.Name}}').stdout.splitlines()
        full.check(not any(n.startswith(PROJECT) for n in names),'Restore namespace is not empty')
    model=json.loads(source('--profile','*','config','--format','json').stdout)
    model=json.loads(json.dumps(model).replace(full.PROJECT,PROJECT).replace(str(full.STATE).replace('\\','\\\\'),str(state).replace('\\','\\\\')))
    model['name']=PROJECT
    for service in model['services'].values():
        service.pop('ports',None)
        for net in service.get('networks',{}).values():
            if isinstance(net,dict) and net.get('ipv4_address')==full.PROXY_IP:net['ipv4_address']='10.253.246.25'
    model['networks']['core']['ipam']['config'][0]['subnet']='10.253.246.0/27'
    for m in model['services']['materialize']['volumes']:
        if m['type']=='bind' and Path(m['source']).resolve()==full.STATE.resolve():m['source']=str(state)
    for group in ('networks','volumes'):
        full.check(all(not v.get('external') and v['name'].startswith(PROJECT+'_') for v in model[group].values()),'Foreign restore resource')
    full.check(all(not s.get('ports') for s in model['services'].values()),'Restore must have no published ports')
    for n,s in model['services'].items():
        for m in s.get('volumes',[]):
            if m['type']=='bind':full.check(n=='materialize' and m.get('read_only') and Path(m['source']).resolve() in (state.resolve(),(full.HERE/'materialize.sh').resolve()),'Foreign restore bind')
    existing=full.run('docker','network','inspect',*full.run('docker','network','ls','-q').stdout.split()).stdout
    full.check('10.253.246.' not in existing,'Restore subnet already in use')
    work.mkdir(mode=0o700);state.mkdir(mode=0o700)
    jwks_witness=public_witness()
    config=work/'compose.restore.json';config.write_text(json.dumps(model,indent=2)+'\n',encoding='utf-8')
    def dest(*args,data=None,timeout=240):
        p=subprocess.run(['docker','compose','-p',PROJECT,'--project-directory',str(full.ROOT),'-f',str(config),*args],
                         input=data,capture_output=True,timeout=timeout,cwd=full.ROOT)
        full.check(p.returncode==0,'Disposable restore Compose failed: '+args[0]+'; secret output withheld')
        return p
    key=AESGCM.generate_key(256);(state/'backup.key').write_bytes(key);(state/'backup.key').chmod(0o600)
    cipher=AESGCM(key)
    def seal(name,data):
        nonce=os.urandom(12);(work/(name+'.aesgcm')).write_bytes(nonce+cipher.encrypt(nonce,data,name.encode()))
    def unseal(name):
        b=(work/(name+'.aesgcm')).read_bytes();return cipher.decrypt(b[:12],b[12:],name.encode())
    redis_image=model['services']['redis']['image']
    source_running=False
    try:
        source('stop','--timeout','45',*WRITERS,'redis')
        # All app/identity/Risk writers are stopped for one cross-schema checkpoint.
        dump=source('exec','-T','mysql','mysqldump','--defaults-extra-file=/fixture/root.cnf','--single-transaction',
            '--set-gtid-purged=OFF','--no-tablespaces','--hex-blob','--add-drop-database','--databases',
            'pd_staging_school','pd_staging_risk','pd_staging_keycloak',timeout=120).stdout.encode()
        seal('sql',dump)
        redis=subprocess.run(['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--user','999:999',
            '--mount',f'type=volume,source={full.PROJECT}_redis-data,target=/data,readonly',
            '--entrypoint','tar',redis_image,'-C','/data','-cf','-','.'],capture_output=True,check=True,timeout=90).stdout
        seal('redis',redis)
        archive=io.BytesIO()
        with tarfile.open(fileobj=archive,mode='w') as t:
            for p in full.STATE.rglob('*'):
                rel=p.relative_to(full.STATE)
                if p.is_file() and (rel.parts[0] in ROOTS or len(rel.parts)==1 and not p.name.startswith('phase2-')):
                    t.add(p,arcname=rel.as_posix(),recursive=False)
        seal('state',archive.getvalue())
        print('PASS encrypted consistent School/Keycloak/Risk and stopped Redis checkpoint; synthetic state only',flush=True)
        with tarfile.open(fileobj=io.BytesIO(unseal('state'))) as t:
            full.check(all(m.isfile() and not Path(m.name).is_absolute() and '..' not in Path(m.name).parts for m in t.getmembers()),'Unsafe state archive')
            t.extractall(state,filter='data')
        (state/'owner').write_text(PROJECT)
        (state/'phase2-restore-public-witness.json').write_text(json.dumps(jwks_witness)+'\n')
        for role,name in (('keycloak','keycloak.conf'),('installer','keycloak.conf'),('gateway','application.properties')):
            p=state/role/name;p.write_text(p.read_text(encoding='utf-8').replace(full.PROXY_IP+'/32','10.253.246.25/32'),encoding='utf-8')
        dest('run','--rm','--no-deps','materialize')
        dest('up','-d','--wait','--wait-timeout','160','mysql','crl')
        dest('exec','-T','mysql','mysql','--defaults-extra-file=/fixture/root.cnf','--binary-mode',data=unseal('sql'))
        dest('create','redis')
        redis_data=unseal('redis')
        with tarfile.open(fileobj=io.BytesIO(redis_data)) as t:
            full.check(all((m.isdir() or m.isfile()) and not Path(m.name).is_absolute() and '..' not in Path(m.name).parts for m in t.getmembers()),'Unsafe Redis archive')
        subprocess.run(['docker','run','--rm','-i','--network','none','--read-only','--cap-drop','ALL','--user','999:999',
            '--mount',f'type=volume,source={PROJECT}_redis-data,target=/data','--entrypoint','sh',redis_image,
            '-ec','test -z "$(ls -A /data)"; tar -C /data -xf -'],input=redis_data,capture_output=True,check=True,timeout=90)
        complete(source,dest,work,state)
    finally:
        try:dest('stop','--timeout','45',*full.rc.HEALTHY,'crl')
        finally:
            restore_source(source)


if __name__=='__main__':
    try:
        if sys.argv[1:]==["--resume-checkpoint"]:resume()
        elif sys.argv[1:]==["--resume-auth"]:resume(auth_only=True)
        else:main()
    except Exception as e:
        print('FAIL restore '+type(e).__name__+'; sensitive output withheld',flush=True)
        raise SystemExit(1)
