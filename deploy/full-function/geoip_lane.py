"""GeoIP lifecycle rehearsal; only retained disposable Phase2 stores, no promotion.

No published ports, account reset, image rebuild, original data or MMDB access.
Readers load in memory: verified data selection MUST be followed by a controlled
isolated Risk restart and successful health/lookup; never pretend a hot reload.
"""
import datetime as dt
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import time
import zipfile
import geoip_data as g

full=g.full
RESTORE='zt-full-function-phase2-restore'
NAME='zt-full-function-phase21a-geoip-risk'
OUT=g.EVIDENCE
STATE=full.OUT/'phase2/restore/private'


def save(name,data):
    (OUT/name).write_text(json.dumps(data,indent=2)+'\n',encoding='utf-8')


def snapshot():
    ids=full.run('docker','ps','-aq').stdout.split()
    rows=json.loads(full.run('docker','inspect',*ids).stdout)
    return {x['Id']:{'name':x['Name'],'image':x['Image'],'running':x['State']['Running'],
        'mounts':sorted([{k:m.get(k) for k in ('Type','Name','Source','Destination','RW')} for m in x['Mounts']],key=lambda m:m['Destination']),
        'networks':sorted(x['NetworkSettings']['Networks'])} for x in rows}


def copied_file(container,path):
    p=subprocess.run(['docker','cp',container+':'+path,'-'],capture_output=True,check=True)
    with tarfile.open(fileobj=io.BytesIO(p.stdout)) as archive:
        return archive.extractfile(archive.getmembers()[0]).read()


def policy_inventory():
    policies={}
    for label,name in [('legacy','zerotrust-legacy-integration-20261026-risk'),('full_function',full.PROJECT+'-risk-1')]:
        x=json.loads(full.run('docker','inspect',name).stdout)[0]
        env=dict(e.split('=',1) for e in x['Config']['Env'])
        with zipfile.ZipFile(io.BytesIO(copied_file(name,'/app/application.jar'))) as jar:
            text=jar.read('BOOT-INF/classes/application.properties').decode()
        text+='\n'+copied_file(name,'/run/demo/application.properties').decode()
        props={}
        for line in text.splitlines():
            if '=' not in line or line.lstrip().startswith('#'):continue
            k,v=line.split('=',1)
            if not k.startswith(('risk.policy.network-risk.','risk.policy.weights.','risk.policy.thresholds.')):continue
            # Empty ${VAR:} means an empty list, not an UNSET sentinel.
            def replace(m):
                key,sep,default=m[1].partition(':')
                return env[key] if key in env else default if sep else '<UNSET>'
            props[k]=re.sub(r'\$\{([^}]+)\}',replace,v)
        policies[label]=props
    inventory={'effective_values':{},'network_lists':{},'correction':'Phase2 parser incorrectly counted ${VAR:} as one <UNSET> entry; original receipt retained',
        'legacy_database_copied':False,'network_history':'No previous-IP/country/ASN movement scoring in verified implementation'}
    for key in sorted(set(policies['legacy'])|set(policies['full_function'])):
        a=policies['legacy'].get(key);b=policies['full_function'].get(key)
        if key.endswith(('cidrs','country-codes')):
            aa=[v for v in (a or '').split(',') if v.strip()];bb=[v for v in (b or '').split(',') if v.strip()]
            inventory['network_lists'][key]={'legacy_entries':len(aa),'full_function_entries':len(bb),'identical':aa==bb}
        elif not key.endswith('database-path'):
            inventory['effective_values'][key]={'legacy':a,'full_function':b,'equal':a==b}
    save('policy-corrected.json',inventory)


def main():
    OUT.mkdir(exist_ok=True);full.configure()
    full.check((STATE/'owner').read_text()==RESTORE,'Wrong synthetic state')
    resume=sys.argv[1:]==['--resume']
    if resume:
        before=json.loads((OUT/'protected-before.json').read_text())
        for x in before.values():x['mounts'].sort(key=lambda m:m['Destination'])
        now=snapshot();full.check(all(now.get(k)==v for k,v in before.items()),'Existing state differs before resume')
    else:before=snapshot();save('protected-before.json',before)
    protected=json.loads((full.ROOT/'target/full-function-20261111/protected-before.json').read_text())
    if not resume:policy_inventory()
    receipt=json.loads((full.OUT/'phase2/locking-candidate-image.json').read_text());image=receipt['image']
    full.check(full.run('docker','image','inspect','--format','{{.Id}}',image).stdout.strip()==receipt['id'],'Image drift')
    rows=json.loads(full.run('docker','inspect',*full.run('docker','ps','-aq','--filter','label=com.docker.compose.project='+RESTORE).stdout.split()).stdout)
    services={}
    for x in rows:
        full.check(not x['State']['Running'] and not x['HostConfig']['PortBindings'],'Disposable lane must be stopped and unpublished')
        full.check(x['Config']['Labels'].get('io.zerotrust.scope')==RESTORE and all(m['Type']=='volume' and m['Name'].startswith(RESTORE+'_') for m in x['Mounts']),'Foreign disposable state')
        services[x['Config']['Labels']['com.docker.compose.service']]=x['Id']
    full.check(resume or full.run('docker','inspect',NAME,check=False).returncode!=0,'GeoIP lane exists; inspect/resume explicitly, never overwrite')
    acquisition=json.loads((OUT/'acquisition.json').read_text());release=acquisition['release'];folder=g.DATA/'releases'/release
    if not resume:g.activate(release)
    lifecycle=json.loads((OUT/'lifecycle.json').read_text()) if resume else [];created=[];started=[]
    def record(case,**values):
        lifecycle.append({'case':case,'status':'PASS',**values});save('lifecycle.json',lifecycle)
        print('PASS '+case,flush=True)
    def start(service):
        full.run('docker','start',services[service]);started.append(service)
        deadline=time.monotonic()+180
        while True:
            x=json.loads(full.run('docker','inspect',services[service]).stdout)[0]
            full.check(x['State']['Running'],'Disposable '+service+' exited')
            if x['State'].get('Health',{}).get('Status')=='healthy':break
            full.check(time.monotonic()<deadline,'Disposable '+service+' health timeout');time.sleep(2)
    def risk(name,data,healthy=True):
        config={'risk.policy.network-risk.geoip.enabled':True,'risk.policy.network-risk.geoip.city-database-path':'/geoip/GeoLite2-City.mmdb',
                'risk.policy.network-risk.geoip.asn-database-path':'/geoip/GeoLite2-ASN.mmdb'}
        existing=full.run('docker','inspect',name,check=False)
        if existing.returncode==0:
            x=json.loads(existing.stdout)[0]
            full.check(resume and name==NAME and not x['State']['Running'] and x['Image']==receipt['id'] and x['Config']['Labels'].get('io.zerotrust.scope')==NAME and not x['HostConfig']['PortBindings'],'Unsafe resume target')
            full.check(sorted(m['Destination'] for m in x['Mounts'])==['/geoip','/run/demo'] and all(not m['RW'] for m in x['Mounts']),'Resume mount drift')
            full.check(next(m for m in x['Mounts'] if m['Destination']=='/run/demo').get('Name')==RESTORE+'_risk-config','Foreign resume config')
            full.check(next(m for m in x['Mounts'] if m['Destination']=='/geoip')['Source'].replace('\\','/').lower().endswith(str(data).replace('\\','/').lower().removeprefix('c:')),'Foreign resume dataset')
        else:full.run('docker','create','--name',name,'--label','io.zerotrust.scope='+NAME,'--network',RESTORE+'_core','--network-alias','risk',
            '--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges','--read-only','--tmpfs','/tmp:mode=1777','--memory','640m',
            '--env','SPRING_APPLICATION_JSON='+json.dumps(config),'--mount',f'type=volume,source={RESTORE}_risk-config,target=/run/demo,readonly',
            '--mount',f'type=bind,source={data},target=/geoip,readonly',image)
        created.append(name);full.run('docker','start',name);wait_risk(name,healthy)
    def wait_risk(name,healthy=True):
        deadline=time.monotonic()+150
        while True:
            x=json.loads(full.run('docker','inspect',name).stdout)[0];full.check(x['State']['Running'],'GeoIP Risk exited')
            p=full.run('docker','exec',name,'java','@/run/demo/jvm.args','-cp','/app/tools','Health','https://risk:8443/actuator/health', '200' if healthy else '503',check=False)
            if p.returncode==0:break
            full.check(time.monotonic()<deadline,'GeoIP Risk health timeout');time.sleep(2)
    def verify(mode,name):
        result=full.run('docker','run','--rm','--name',NAME+'-check','--network',RESTORE+'_core','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--memory','1g','--shm-size','256m',
            '--mount',f'type=bind,source={STATE},target=/private,readonly','--mount',f'type=bind,source={full.HERE},target=/tests,readonly',
            '--mount',f'type=bind,source={OUT},target=/results','zt-full-function/browser:20261111-1','/tests/geoip_verify.py',mode,timeout=240,check=False)
        safe='\n'.join(x for x in result.stdout.splitlines() if x.startswith(('PASS ','FAIL ')))
        print(safe,flush=True);full.check(result.returncode==0,'Targeted GeoIP '+mode+' failed; sanitized receipt retained')
        traces=[]
        for line in (full.run('docker','logs',name).stdout+full.run('docker','logs',name).stderr).splitlines():
            if 'ZEROTRUST_RISK_SCORE_TRACE ' in line:
                traces.append(json.loads(line.split('ZEROTRUST_RISK_SCORE_TRACE ',1)[1]))
        save('risk-traces-'+mode+'.json',traces)
    try:
        # Reject malformed/type-swapped data before changing selected or loaded pair.
        bad=g.PRIVATE/'negative-tests';bad.mkdir(exist_ok=True)
        (bad/'GeoLite2-City.mmdb').write_bytes(b'corrupt declared negative-test fixture')
        shutil.copyfile(folder/'GeoLite2-ASN.mmdb',bad/'GeoLite2-ASN.mmdb')
        for label,clock in ([] if resume else [('corrupt',None),('stale-clock', (dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=32)).isoformat())]):
            try:g.probe(bad if label=='corrupt' else folder,clock)
            except RuntimeError:record('Preflight rejects '+label,clock_simulated=label=='stale-clock')
            else:raise RuntimeError('Bad dataset accepted')
        swapped=g.PRIVATE/'negative-swapped';swapped.mkdir(exist_ok=True)
        shutil.copyfile(folder/'GeoLite2-ASN.mmdb',swapped/'GeoLite2-City.mmdb');shutil.copyfile(folder/'GeoLite2-City.mmdb',swapped/'GeoLite2-ASN.mmdb')
        if not resume:
            try:g.probe(swapped)
            except RuntimeError:record('Preflight rejects swapped database types')
            else:raise RuntimeError('Wrong database type accepted')
        for service in ('mysql','redis','crl','keycloak'):start(service)
        risk(NAME,folder)
        for service in ('backend','frontend','gateway','ingress'):start(service)
        verify('browser' if resume else 'full',NAME);record('Real MMDB authenticated service and HTTPS browser boundary',image_id=receipt['id'],running_profile_promoted=False)
        full.run('docker','restart','--timeout','45',NAME);wait_risk(NAME);verify('restart',NAME)
        record('Controlled restart reloads real City/ASN; state and V5 retained')
        # Exercise a new release-directory lifecycle using the SAME vendor build.
        # Never call this a newer vendor dataset or fetch unchanged data again.
        second=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+release.split('-')[-1]
        full.check(second!=release,'Restage identifier collision')
        second_folder=g.DATA/'releases'/second;shutil.copytree(folder,second_folder)
        manifest=json.loads((second_folder/'manifest.json').read_text());manifest.update(release=second,lifecycle_exercise_same_vendor_build=True)
        (second_folder/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        g.activate(second)
        full.run('docker','stop','--timeout','45',NAME)
        risk(NAME+'-update',second_folder);verify('update',NAME+'-update')
        record('Atomic pair selection plus controlled reader replacement',new_vendor_build=False,same_build_lifecycle_exercise=True)
        g.activate(release);full.run('docker','stop','--timeout','45',NAME+'-update')
        full.run('docker','start',NAME);wait_risk(NAME);verify('rollback',NAME)
        record('Last-good rollback reloads old verified pair; no user/schema reset')
        full.run('docker','stop','--timeout','45',NAME)
        risk(NAME+'-corrupt',bad,False);verify('corrupt',NAME+'-corrupt')
        record('Defense in depth: bypassed preflight corrupt City produces health DOWN and public-IP INCOMPLETE/STEP_UP, never ALLOW')
    finally:
        for name in reversed(created):full.run('docker','stop','--timeout','45',name,check=False)
        for service in reversed(started):full.run('docker','stop','--timeout','45',services[service],check=False)
        after=snapshot()
        full.check(all(after.get(k)==v for k,v in before.items()),'Existing container identity/config/state changed')
        # Original protection receipt has hashes under files, not container entries.
        file_hashes=protected.get('files',{})
        for path,digest in file_hashes.items():full.check(hashlib.sha256(Path(path).read_bytes()).hexdigest()==digest,'Protected file changed')
        save('preservation.json',{'status':'PASS','existing_containers_unchanged':len(before),'protected_hashes_checked':len(file_hashes),
            'isolated_services_stopped':True,'private_data_only':True,'D17':'PENDING','G8':'INTERNET_NO_GO'})
        print('PASS retained GeoIP lane stopped; existing profiles/locks unchanged',flush=True)


if __name__=='__main__':
    try:main()
    except Exception as e:
        import traceback
        row={'type':type(e).__name__,'line':traceback.extract_tb(e.__traceback__)[-1].lineno}
        if type(e) is RuntimeError:row['reason']=str(e)
        save('lane-failure.json',row);print('BLOCKED '+json.dumps(row),flush=True);raise SystemExit(1)
