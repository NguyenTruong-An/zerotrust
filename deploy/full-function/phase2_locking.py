"""Test new Risk image ONLY on retained disposable restore stores; no promotion."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import time
import zipfile
import operate as full

RESTORE='zt-full-function-phase2-restore'
NAME='zt-full-function-phase2-locking-risk'


def main():
    full.configure();out=full.OUT/'phase2';work=out/'locking';work.mkdir(exist_ok=True)
    state=out/'restore/private';full.check((state/'owner').read_text()==RESTORE,'Wrong disposable restore state')
    receipt=json.loads((out/'locking-candidate-image.json').read_text());image=receipt['image']
    full.check(full.run('docker','image','inspect','--format','{{.Id}}',image).stdout.strip()==receipt['id'],'Candidate image drift')
    ids=full.run('docker','ps','-aq','--filter','label=com.docker.compose.project='+RESTORE).stdout.split()
    rows=json.loads(full.run('docker','inspect',*ids).stdout);services={}
    for x in rows:
        full.check(x['Config']['Labels'].get('io.zerotrust.scope')==RESTORE and not x['HostConfig']['PortBindings'],'Foreign or published restore resource')
        full.check(all(m['Type']=='volume' and m['Name'].startswith(RESTORE+'_') for m in x['Mounts']),'Foreign restore mount')
        full.check(not x['State']['Running'],'Retained restore must start stopped; do not interfere with another run')
        services[x['Config']['Labels']['com.docker.compose.service']]=x['Id']
    full.check(full.run('docker','container','inspect',NAME,check=False).returncode!=0,'Candidate container already exists; inspect rather than replace')
    def start(service):
        ident=services[service];full.run('docker','start',ident)
        deadline=time.monotonic()+180
        while True:
            x=json.loads(full.run('docker','inspect',ident).stdout)[0]
            full.check(x['State']['Running'],'Disposable service exited: '+service)
            if x['State'].get('Health',{}).get('Status')=='healthy':break
            full.check(time.monotonic()<deadline,'Disposable service unhealthy: '+service);time.sleep(2)
    created=False
    try:
        for service in ('mysql','redis','crl','keycloak'):start(service)
        full.run('docker','create','--name',NAME,'--label','io.zerotrust.scope='+NAME,'--network',RESTORE+'_core',
            '--network-alias','risk','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges',
            '--read-only','--tmpfs','/tmp:mode=1777','--memory','512m',
            '--mount',f'type=volume,source={RESTORE}_risk-config,target=/run/demo,readonly',image)
        created=True;full.run('docker','start',NAME)
        deadline=time.monotonic()+150
        while True:
            x=json.loads(full.run('docker','inspect',NAME).stdout)[0];full.check(x['State']['Running'],'Risk candidate exited')
            p=full.run('docker','exec',NAME,'java','@/run/demo/jvm.args','-cp','/app/tools','Health','https://risk:8443/actuator/health/readiness','200',check=False)
            if p.returncode==0:break
            full.check(time.monotonic()<deadline,'Risk candidate readiness failed');time.sleep(2)
        for service in ('backend','frontend','gateway','ingress'):start(service)
        r=full.run('docker','run','--rm','--name',NAME+'-check','--network',RESTORE+'_core','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--memory','1g','--shm-size','256m',
            '--mount',f'type=bind,source={state},target=/private,readonly','--mount',f'type=bind,source={full.HERE},target=/tests,readonly',
            '--mount',f'type=bind,source={work},target=/results','zt-full-function/browser:20261111-1','/tests/phase2_verify_locking.py',timeout=240,check=False)
        safe='\n'.join(x for x in r.stdout.splitlines() if x.startswith(('PASS ','FAIL ')))+'\n';(work/'http.log').write_text(safe);print(safe,end='',flush=True)
        full.check(r.returncode==0,'Isolated candidate regression failed; see sanitized receipt')
        def artifact(container):
            raw=subprocess.run(['docker','cp',container+':/app/application.jar','-'],capture_output=True,check=True).stdout
            with tarfile.open(fileobj=io.BytesIO(raw)) as t:data=t.extractfile(t.getmembers()[0]).read()
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                return {k:hashlib.sha256(z.read(k)).hexdigest() for k in z.namelist() if k.startswith('BOOT-INF/') and (k.endswith('.class') or k.endswith('.jar'))}
        old=artifact(full.PROJECT+'-risk-1');new=artifact(NAME)
        changed=sorted(k for k in set(old)|set(new) if old.get(k)!=new.get(k))
        family='BOOT-INF/classes/com/zerotrust/risk/repository/DeviceTrustStateRepository'
        allowed={family+'.class',family+'$SubjectState.class',family+'$Revocation.class'}
        full.check(family+'.class' in changed and set(changed)<=allowed,'Unexpected executable/dependency change: '+str(changed))
        (work/'candidate-acceptance.json').write_text(json.dumps({'status':'PASS','image':receipt,'changed_executable_entries':changed,'deployed_to_active_full_function':False,'stores_reset_or_imported':False,'public_ports':0,'D17':'PENDING','G8':'INTERNET_NO_GO'},indent=2)+'\n')
        print('PASS only DeviceTrustStateRepository class family changed; dependency bytes, B0 and V5 retained; old profile/release pins unchanged',flush=True)
    finally:
        if created:full.run('docker','stop','--timeout','45',NAME,check=False)
        for service in ('ingress','gateway','frontend','backend','keycloak','crl','redis','mysql'):
            full.run('docker','stop','--timeout','45',services[service],check=False)
        print('Retained disposable candidate/stores stopped; active full-function and protected environments not restarted',flush=True)


if __name__=='__main__':
    try:main()
    except Exception as e:
        print('FAIL candidate '+type(e).__name__+'; sensitive output withheld',flush=True);raise SystemExit(1)
