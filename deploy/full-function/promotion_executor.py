"""Scoped executor. Phase2.3A can mutate ONLY the retained disposable restore lane.

No CLI/env/manifest field can authorize the protected active profile. Rehearsal
request signatures identify the harness, never pretend to be owner signatures.
"""
import base64
import contextlib
import datetime as dt
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time
import uuid
import warnings
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,PublicFormat,NoEncryption
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import risk_promotion as r
from promotion_maintenance import Maintenance,consistent_intent

LANE='zt-full-function-phase2-restore'
OUT=r.ROOT/(r.PREFIX+'phase23a')
PRIVATE=OUT/'private'
MANIFEST=OUT/'execution-manifest.json'
AUTHORITY=(Path.home()/'.codex/attachments/0786b0b9-5c4a-40b3-b34e-ee2f811cabff/Pasted text.txt')
AUTHORITY_SHA='9beaf911e9369cca39b5648158fef3ae94b0d954d3178861268822d3f6e3200d'
HELPER='zt-full-function/browser:20261111-1'
HELPER_ID='sha256:44d64ab7d73aa62c6fbab63c7b63a9f3ee226e966c1895e5707d7bd7762c0ac2'
SERVICES=('mysql','redis','crl','keycloak','risk','backend','frontend','gateway','ingress')
STOP_ORDER=('ingress','gateway','frontend','backend','risk','keycloak','redis','crl','mysql')
WRITERS=('ingress','gateway','frontend','backend','risk','keycloak')
CORE=LANE+'_core'
EXPECTED_KIND='DISPOSABLE_REHEARSAL_NOT_OWNER_CUTOVER_APPROVAL'


def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()


def atomic(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    os.replace(tmp,path)


def jwrite(path,value):atomic(path,canonical(value)+b'\n')


def scoped(project):
    r.need(project==LANE,'PHASE23A_SCOPE_CEILING_PROTECTED_OR_UNKNOWN_PROJECT')


def storage_guard():
    free=shutil.disk_usage(r.ROOT.anchor).free
    r.need(free>=15*1024**3,'STORAGE_BELOW_15_GIB_NO_BACKUP_OR_RESTORE')
    if free<20*1024**3:warnings.warn('C: free space below 20 GiB before backup/restore; cleanup remains postponed',RuntimeWarning)
    return {'free_bytes':free,'warning_below_20_GiB':free<20*1024**3}


def authority():
    r.need(AUTHORITY.is_file() and r.sha_file(AUTHORITY)==AUTHORITY_SHA,'CURRENT_USER_REHEARSAL_AUTHORITY_MISSING')


def private_acl():
    r.local_path(r.ROOT,str(PRIVATE.relative_to(r.ROOT)).replace('\\','/'))
    if os.name=='nt':
        quoted=str(PRIVATE).replace("'","''")
        code=("$ErrorActionPreference='Stop'; $p='"+quoted+"'; $sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; "
            "$paths=@($p)+[System.IO.Directory]::GetFiles($p)+[System.IO.Directory]::GetFiles($p+'\\keys'); $ok=$true; "
            "foreach($item in $paths){if([System.IO.Directory]::Exists($item)){$a=[System.IO.Directory]::GetAccessControl($item)}"
            "else{$a=[System.IO.File]::GetAccessControl($item)}; foreach($e in $a.Access){"
            "$s=$e.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value; "
            "if($s -notin @($sid,'S-1-5-18') -or $e.AccessControlType -ne 'Allow'){$ok=$false}}}; "
            "if(-not $ok -or -not [System.IO.Directory]::GetAccessControl($p).AreAccessRulesProtected){exit 23}; "
            "[Console]::WriteLine('OWNER_SYSTEM_ONLY')")
        p=subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command',code],capture_output=True,timeout=20)
        r.need(p.returncode==0 and p.stdout.strip()==b'OWNER_SYSTEM_ONLY','PRIVATE_ACL_NOT_OWNER_SYSTEM_ONLY')
    else:r.need(PRIVATE.stat().st_mode&0o077==0,'PRIVATE_PERMISSIONS')


def public_witness(row):
    w=r.container_witness(row)
    for key in ('entrypoint','cmd'):w[key+'_sha256']=r.sha(canonical(w.pop(key)))
    return w


def safe_archive(data):
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        members=archive.getmembers()
        r.need(len(members)<100000 and sum(m.size for m in members)<512*1024**2,'ARCHIVE_SIZE')
        r.need(all((m.isdir() or m.isfile()) and not Path(m.name).is_absolute() and '..' not in Path(m.name).parts
                   and '\\' not in m.name and ':' not in m.name for m in members),'ARCHIVE_PATH_OR_LINK')
        return {m.name:r.sha(archive.extractfile(m).read()) for m in members if m.isfile()}


class ProjectLock:
    def __enter__(self):
        private_acl()
        self.f=(PRIVATE/'operation.lock').open('a+b')
        try:
            if os.fstat(self.f.fileno()).st_size==0:self.f.write(b'0');self.f.flush()
            self.f.seek(0)
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(self.f.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(self.f.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:self.f.close();raise r.Rejected('PROJECT_OPERATION_LOCK_BUSY') from None
        return self
    def __exit__(self,*args):
        if os.name=='nt':
            import msvcrt
            self.f.seek(0);msvcrt.locking(self.f.fileno(),msvcrt.LK_UNLCK,1)
        self.f.close()


def state_key():return (PRIVATE/'state.key').read_bytes()


def sealed_write(path,body):
    jwrite(path,{'body':body,'mac':hmac.digest(state_key(),canonical(body),'sha256').hex()})


def sealed_read(path):
    v=r.json_bytes(path.read_bytes())
    r.need(hmac.compare_digest(v['mac'],hmac.digest(state_key(),canonical(v['body']),'sha256').hex()),'JOURNAL_OR_STATE_TAMPER')
    return v['body']


def verify_request(envelope,m,manifest_sha,operation,used,now=None):
    """Pure checks, with a fixed scoped trust anchor; caller holds project lock."""
    scoped(m['project']);authority();now=int(time.time()) if now is None else now
    p=envelope['payload'];scoped(p['project'])
    r.need(set(p)=={'id','project','manifest_sha256','operation','old_image','new_image','config_sha256','dataset_sha256',
                   'maintenance','checkpoint','rollback','issued','expires','authority','issuer','recover_of','recover_target'},'REQUEST_SHAPE')
    r.need(re.fullmatch('[0-9a-f]{32}',p['id']) is not None,'REQUEST_ID')
    r.need(p['id'] not in used,'REQUEST_ALREADY_USED')
    r.need(type(p['issued']) is int and type(p['expires']) is int and p['issued']<=now+5 and now<p['expires']<=p['issued']+600,'REQUEST_STALE')
    expected={'manifest_sha256':manifest_sha,'operation':operation,'old_image':r.OLD,'new_image':r.NEW,
        'config_sha256':r.sha(canonical(m['proposed'])),'dataset_sha256':r.sha(canonical(m['geoip'])),
        'maintenance':list(WRITERS),'rollback':r.OLD,'authority':AUTHORITY_SHA,
        'issuer':'TEST_HARNESS_CURRENT_USER_REHEARSAL_ONLY'}
    r.need(all(p.get(k)==v for k,v in expected.items()),'REQUEST_BINDING_MISMATCH')
    r.need(p['recover_of'] is None or re.fullmatch('[0-9a-f]{32}',p['recover_of']) is not None,'RECOVERY_REFERENCE')
    r.need(p['recover_target'] in (None,'BASELINE','PROMOTED','STOPPED'),'RECOVERY_TARGET')
    try:
        Ed25519PublicKey.from_public_bytes((PRIVATE/'rehearsal-auth.pub').read_bytes()).verify(base64.b64decode(envelope['signature'],validate=True),canonical(p))
    except Exception:raise r.Rejected('REHEARSAL_SIGNATURE_INVALID') from None
    return p


class Docker:
    def __init__(self):
        r.ReadOnlyDocker().local()
    def raw(self,*args,data=None,timeout=180):
        try:p=subprocess.run(args,input=data,capture_output=True,timeout=timeout,cwd=r.ROOT)
        except (OSError,subprocess.TimeoutExpired):raise r.Rejected('SCOPED_COMMAND_TIMEOUT_OR_UNAVAILABLE') from None
        r.need(p.returncode==0,'SCOPED_COMMAND_FAILED:'+args[0]+':'+args[1])
        return p.stdout
    def rows(self):
        ids=self.raw('docker','ps','-aq').decode().split();return r.json_bytes(self.raw('docker','inspect',*ids))
    def inspect(self,name):return r.json_bytes(self.raw('docker','inspect',name))[0]
    def image(self,image):return r.json_bytes(self.raw('docker','image','inspect',image))[0]
    def volumes(self,names):return r.json_bytes(self.raw('docker','volume','inspect',*names))
    def networks(self,names):return r.json_bytes(self.raw('docker','network','inspect',*names))
    def copied(self,name,path):
        scoped_name(name)
        raw=self.raw('docker','cp',name+':'+path,'-')
        with tarfile.open(fileobj=io.BytesIO(raw)) as t:
            files=[x for x in t.getmembers() if x.isfile()];r.need(len(files)==1,'COPY_LAYOUT')
            return t.extractfile(files[0]).read()
    def owned(self,name):
        x=self.inspect(name);r.need((x['Config'].get('Labels') or {}).get('io.zerotrust.scope')==LANE,'FOREIGN_CONTAINER')
        r.need(not x['HostConfig'].get('PortBindings'),'PUBLIC_PORT_REJECTED');return x
    def start(self,name):self.owned(name);self.raw('docker','start',name)
    def stop(self,name):
        if self.owned(name)['State']['Running']:self.raw('docker','stop','--timeout','45',name,timeout=70)
    def health(self,name,promoted=False,timeout=180):
        deadline=time.monotonic()+timeout
        while True:
            x=self.owned(name);r.need(x['State']['Running'],'OWNED_SERVICE_EXITED')
            if promoted:
                p=subprocess.run(['docker','exec',name,'java','@/run/demo/jvm.args','-cp','/app/tools','Health',
                    'https://risk:8443/actuator/health','200'],capture_output=True,timeout=20)
                if p.returncode==0:return
            elif x['State'].get('Health',{}).get('Status')=='healthy':return
            r.need(time.monotonic()<deadline,'OWNED_SERVICE_HEALTH_TIMEOUT');time.sleep(2)
    def sql(self,name,statement):
        self.owned(name)
        r.need(statement.lstrip().startswith(('SELECT ','SHOW ')),'READ_SQL_ONLY')
        return self.raw('docker','exec',name,'mysql','--defaults-extra-file=/fixture/root.cnf','--binary-as-hex','--batch','--raw','--skip-column-names','-e',statement)


def scoped_name(name):r.need(name.startswith(LANE+'-'),'FOREIGN_CONTAINER_NAME')


class Executor:
    def __init__(self,path=MANIFEST,docker=None,hook=None):
        self.path=Path(path)
        r.need(self.path.resolve()==MANIFEST.resolve(),'EXECUTION_MANIFEST_LOCATION')
        self.m=r.json_bytes(self.path.read_bytes());scoped(self.m['project'])
        self.digest=r.sha_file(self.path);self.d=docker or Docker();self.hook=hook or (lambda stage:None)
        self.maintenance=Maintenance(self)
    def scope_check(self):scoped(self.m['project'])
    def state(self):
        s=sealed_read(PRIVATE/'state.json');r.need(s['manifest']==self.digest,'STATE_MANIFEST');return s
    def save_state(self,s):sealed_write(PRIVATE/'state.json',s)
    def name(self,service):return self.m['services'][service]['name']
    def current(self):return self.state()['risk']
    def journal(self,op):return PRIVATE/'journal'/(op+'.json')
    def stage(self,j,stage,**fields):
        j.update(stage=stage,updated=time.time(),**fields);sealed_write(self.journal(j['id']),j);self.hook(stage)
    def unfinished(self):
        return [sealed_read(p) for p in (PRIVATE/'journal').glob('*.json') if sealed_read(p)['status']=='RUNNING']
    def new_operation(self,envelope,operation):
        used={p.stem for p in (PRIVATE/'used').glob('*.json')}
        p=verify_request(envelope,self.m,self.digest,operation,used)
        if operation!='recover':r.need(not self.unfinished(),'INTERRUPTED_OPERATION_REQUIRES_RECOVER')
        self.validate(require_healthy=False)
        running={s:self.d.owned(self.current() if s=='risk' else self.name(s))['State']['Running'] for s in SERVICES}
        if operation in ('backup-only','apply','rollback','restart'):consistent_intent(running)
        sealed_write(PRIVATE/'used'/(p['id']+'.json'),{'request_sha256':r.sha(canonical(envelope)),'operation':operation,'at':time.time()})
        j={'id':p['id'],'operation':operation,'manifest':self.digest,'status':'RUNNING','stage':'AUTHORIZED','request':p,
           'before':self.state(),'running_before':running}
        sealed_write(self.journal(j['id']),j);return j
    def finish(self,j,**fields):self.stage(j,'DONE',status='DONE',**fields)
    def validate(self,require_healthy=False):
        scoped(self.m['project']);authority()
        r.need(self.m['active_proposal_sha256']==r.sha_file(r.DEFAULT_MANIFEST),'ACTIVE_PROPOSAL_DRIFT')
        v1=r.json_bytes(r.DEFAULT_MANIFEST.read_bytes())
        r.need(self.m['version']==1 and self.m['kind']==EXPECTED_KIND
            and self.m['authority_sha256']==AUTHORITY_SHA,'EXECUTION_DESCRIPTOR_KIND')
        r.need(set(self.m['services'])==set(SERVICES) and self.m['policy']==v1['policy'] and self.m['geoip']==v1['geoip']
            and self.m['receipts']==v1['receipts'],'UNAPPROVED_EXECUTION_DESCRIPTOR')
        r.need(self.m['proposed']=={'image':r.NEW,'application':r.GEO,'security':v1['override']['security'],'rollback':r.OLD},'PROPOSED_CONFIGURATION_DRIFT')
        for e in self.m['receipts']:r.need(r.sha_file(r.local_path(r.ROOT,e['path']))==e['sha256'],'BASE_RECEIPT_DRIFT')
        r.need(r.sha_file(r.local_path(r.ROOT,r.SOURCE))==r.SOURCE_HASH,'SOURCE_DRIFT')
        ro=r.ReadOnlyDocker();r.need(ro.head()==self.m['review_HEAD'] and not ro.build_input_changes(r.BUILD_HEAD,self.m['review_HEAD']),'SOURCE_HEAD_DRIFT')
        for ident in (r.OLD,r.NEW):
            x=self.d.image(ident);r.need(x['Id']==ident and x['Architecture']=='amd64' and x['Os']=='linux','IMAGE_DRIFT')
        r.need(self.d.image(HELPER)['Id']==HELPER_ID,'HELPER_IMAGE_DRIFT')
        rows=self.d.rows();lookup={x['Id']:x for x in rows}
        for service,e in self.m['services'].items():
            r.need(e['id'] in lookup,'MISSING_BASE_SERVICE');x=lookup[e['id']]
            r.need(public_witness(x)==e['witness'],'BASE_CONTAINER_CONFIG_DRIFT');self.d.owned(e['name'])
            r.need(x['Image']==v1['baseline_runtime'][service]['image'],'BASE_SERVICE_IMAGE_DRIFT')
            r.need(all(z['Type']=='volume' and z.get('Name','').startswith(LANE+'_') for z in x['Mounts']),'FOREIGN_MOUNT')
        for x in self.d.volumes(self.m['volumes']):
            r.need((x.get('Labels') or {}).get('com.docker.compose.project')==LANE,'FOREIGN_VOLUME')
        nets={n['Name']:r.network_witness(n) for n in self.d.networks(list(self.m['networks']))}
        r.need(nets==self.m['networks'] and nets[CORE]['Internal'],'NETWORK_DRIFT')
        risk=self.current();running=[]
        for x in rows:
            if x['State']['Running'] and CORE in x['NetworkSettings']['Networks']:
                labels=x['Config'].get('Labels') or {};aliases=x['NetworkSettings']['Networks'][CORE].get('Aliases') or []
                if 'risk' in aliases or x['Image'] in (r.OLD,r.NEW) or labels.get('io.zerotrust.role')=='risk':running.append(x['Id'])
        allowed={self.d.owned(risk)['Id']}
        if self.unfinished():
            for j in self.unfinished():
                if j.get('new_id'):allowed.add(j['new_id'])
                if j['operation']=='rollback':
                    # An interrupted rollback may already have started OLD,
                    # while the durable selection still records PROMOTED.
                    # Permit only the immutable OLD identity and the recorded,
                    # verified promoted identity, never two running writers.
                    allowed.add(self.m['services']['risk']['id'])
                    self.verify_new(j['before']['risk'])
                    allowed.add(self.d.owned(j['before']['risk'])['Id'])
        r.need(len(running)<=1 and set(running)<=allowed,'CONFLICTING_RISK_WRITER')
        self.verify_config()
        if self.state()['mode']=='PROMOTED':self.verify_new(risk)
        if require_healthy:
            for s in SERVICES:self.d.health(risk if s=='risk' else self.name(s),self.state()['mode']=='PROMOTED' and s=='risk')
        pending=self.unfinished()
        runtime={}
        for service in SERVICES:
            name=risk if service=='risk' else self.name(service)
            row=next((z for z in rows if z['Name']=='/'+name),None) or self.d.owned(name)
            runtime[service]={'name':name,'image':row['Image'],'running':row['State']['Running'],
                'health':row['State'].get('Health',{}).get('Status'),'custom_tls_health_probe':service=='risk' and row['Image']==r.NEW}
        return {'status':'PASS' if not pending else 'OPERATION_RUNNING_OR_RECOVERY_REQUIRED','project':LANE,'mode':self.state()['mode'],'risk':risk,
            'runtime':runtime,'unfinished':[x['id'] for x in pending],'recovery':'new signed scoped recover request; never legacy restart' if pending else None,
            'active_cutover_authorized':False,'D17':'PENDING','G8':'INTERNET_NO_GO'}
    def verify_config(self):
        risk=self.name('risk');cfg=self.m['config']
        app=self.d.copied(risk,'/run/demo/application.properties');jvm=self.d.copied(risk,'/run/demo/jvm.args')
        r.need(r.sha(app)==cfg['app_sha256'] and r.sha(jvm)==cfg['jvm_sha256'],'RISK_CONFIG_DRIFT')
        p=r.properties(app)
        r.need(p.get('server.ssl.enabled')=='true' and 'sslMode=VERIFY_IDENTITY' in p.get('spring.datasource.url',''),'TLS_DISABLED')
        r.need(b'-Dcom.sun.net.ssl.checkRevocation=true' in jvm and b'-Dcom.sun.security.enableCRLDP=true' in jvm,'REVOCATION_DISABLED')
        defaults=r.local_path(r.ROOT,cfg['defaults']['path']);r.need(r.sha_file(defaults)==cfg['defaults']['sha256'],'DEFAULTS_DRIFT')
        env=dict(z.split('=',1) for z in self.d.owned(risk)['Config']['Env'])
        r.need(r.effective_policy(defaults.read_bytes(),app,env)==self.m['policy'],'B0_POLICY_DRIFT')
        for rec in self.m['tls'].values():r.need(r.sha_file(r.local_path(r.ROOT,rec['path']))==rec['sha256'],'TLS_FILE_DRIFT')
        r.tls_validate(*[r.local_path(r.ROOT,self.m['tls'][k]['path']).read_bytes() for k in ('ca','leaf','crl')],dt.datetime.now(dt.timezone.utc))
        for edition,rec in self.m['geoip']['files'].items():
            path=r.local_path(r.ROOT,self.m['geoip']['directory']+'/'+edition+'.mmdb')
            r.need(path.is_file() and r.sha_file(path)==rec['sha256'],'GEOIP_MISSING_OR_CORRUPT')
            built=dt.datetime.fromisoformat(rec['metadata']['build_at'].replace('Z','+00:00'))
            r.need(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=30)<=built,'STALE_GEOIP')
    def verify_new(self,name,operation=None):
        x=self.d.owned(name);h=x['HostConfig'];env=dict(z.split('=',1) for z in x['Config']['Env'])
        labels=x['Config']['Labels']
        r.need(labels.get('io.zerotrust.promotion.manifest')==self.digest and labels.get('io.zerotrust.role')=='risk'
            and (operation is None or labels.get('io.zerotrust.operation')==operation),'PROMOTED_PROVENANCE_LABEL')
        r.need(x['Image']==r.NEW and x['Config']['User']=='10001:10001' and h['ReadonlyRootfs'] and h['CapDrop']==['ALL']
            and 'no-new-privileges' in h['SecurityOpt'] and h['Memory']==640*1024**2 and h['Tmpfs']=={'/tmp':'mode=1777'},'PROMOTED_HARDENING_DRIFT')
        r.need(set(x['NetworkSettings']['Networks'])=={CORE} and not h.get('PortBindings'),'PROMOTED_NETWORK_DRIFT')
        mounts={z['Destination']:z for z in x['Mounts']}
        r.need(set(mounts)=={'/run/demo','/geoip'} and all(not z['RW'] for z in mounts.values())
            and mounts['/run/demo'].get('Name')==LANE+'_risk-config','PROMOTED_MOUNT_DRIFT')
        expected=str(r.local_path(r.ROOT,self.m['geoip']['directory'])).replace('\\','/').lower().removeprefix('c:')
        r.need(mounts['/geoip']['Source'].replace('\\','/').lower().endswith(expected),'PROMOTED_DATASET_DRIFT')
        r.need(json.loads(env.get('SPRING_APPLICATION_JSON','{}'))==r.GEO,'PROMOTED_OVERRIDE_DRIFT')
        r.need(h['RestartPolicy']['Name']=='unless-stopped','PROMOTED_RESTART_POLICY_DRIFT')
    def start_set(self,running,risk=None):
        risk=risk or self.current()
        for s in SERVICES:
            if running.get(s):
                name=risk if s=='risk' else self.name(s);self.d.start(name)
                self.d.health(name,s=='risk' and self.d.inspect(name)['Image']==r.NEW)
    def quiesce(self,j,include_redis=False):
        self.maintenance.enter(j,include_redis)
    def resume_verified(self,j,risk,smoke=True):
        self.maintenance.start_internal(j,risk)
        self.verify_runtime(risk,smoke,internal=True)
        self.maintenance.verified(j)
        self.maintenance.resume(j,risk)
    def helper(self,role,args,mounts=(),data=None,network='none',entrypoint='tar',memory='256m'):
        name=LANE+'-phase23a-'+role+'-'+uuid.uuid4().hex[:8]
        cmd=['docker','run','--rm','--name',name,'--label','io.zerotrust.scope='+LANE,'--network',network,
            '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory',memory,'--tmpfs','/tmp:mode=1777']
        if data is not None:cmd+=['--interactive']
        for m in mounts:cmd+=['--mount',m]
        if entrypoint=='tar':cmd+=['--user','0:0','--cap-add','DAC_READ_SEARCH','--cap-add','CHOWN','--cap-add','FOWNER','--cap-add','DAC_OVERRIDE']
        cmd+=['--entrypoint',entrypoint,HELPER,*args]
        return self.d.raw(*cmd,data=data,timeout=240)
    def read_volume(self,volume):
        r.need(volume in self.m['volumes'] or volume.startswith(LANE+'_phase23restore_'),'FOREIGN_ARCHIVE_VOLUME')
        data=self.helper('read-volume',['-C','/data','-cf','-','.'],[f'type=volume,source={volume},target=/data,readonly'])
        safe_archive(data);return data
    def v5(self,mysql=None):
        raw=self.d.sql(mysql or self.name('mysql'),"SELECT checksum,success FROM pd_staging_risk.flyway_schema_history WHERE version='5'")
        r.need(raw.decode().strip()=='661092940\t1','V5_DRIFT')

    # Operations below only run after a verified one-use scoped request under lock.
    def backup(self,envelope):
        storage_guard()
        with ProjectLock():
            j=self.new_operation(envelope,'backup-only')
            r.need(j['running_before']['mysql'] and j['running_before']['risk'],'CHECKPOINT_REQUIRES_RUNNING_MYSQL_AND_RISK')
            for service,running in j['running_before'].items():
                if running:
                    name=self.current() if service=='risk' else self.name(service)
                    self.d.health(name,service=='risk' and self.d.inspect(name)['Image']==r.NEW)
            key=AESGCM.generate_key(256)
            folder=PRIVATE/'checkpoints'/j['id'];folder.mkdir(parents=True)
            atomic(PRIVATE/'keys'/(j['id']+'.key'),key);cipher=AESGCM(key);files={}
            def seal(label,data):
                nonce=os.urandom(12);blob=nonce+cipher.encrypt(nonce,data,canonical({'project':LANE,'manifest':self.digest,'label':label}))
                atomic(folder/(label+'.aesgcm'),blob);files[label]=r.sha(blob)
                r.need(cipher.decrypt(blob[:12],blob[12:],canonical({'project':LANE,'manifest':self.digest,'label':label}))==data,'CHECKPOINT_AUTHENTICATION')
            try:
                self.quiesce(j,True)
                sql=self.d.raw('docker','exec',self.name('mysql'),'mysqldump','--defaults-extra-file=/fixture/root.cnf','--single-transaction',
                    '--set-gtid-purged=OFF','--no-tablespaces','--hex-blob','--add-drop-database','--databases',
                    'pd_staging_school','pd_staging_risk','pd_staging_keycloak',timeout=120)
                seal('sql',sql);seal('redis',self.read_volume(LANE+'_redis-data'))
                configs={}
                for volume in self.m['volumes']:
                    if volume.endswith('-config'):
                        label='config-'+volume.removeprefix(LANE+'_');seal(label,self.read_volume(volume));configs[volume]=label
                # Exact environment/entrypoint values can contain credentials:
                # retain them only inside authenticated ciphertext, not public
                # manifest witnesses. Include baseline and selected Risk contracts.
                runtime={s:{'config':self.d.owned(self.name(s))['Config'],'host':self.d.owned(self.name(s))['HostConfig']}
                    for s in SERVICES}
                runtime['selected_risk']={'state':self.state(),'config':self.d.owned(self.current())['Config'],'host':self.d.owned(self.current())['HostConfig']}
                seal('runtime-contract',canonical(runtime));seal('execution-manifest',canonical(self.m))
                cp={'id':j['id'],'project':LANE,'manifest':self.digest,'created':time.time(),'files':files,'configs':configs,
                    'dataset':self.m['geoip'],'restore_verified':False,'tables':self.table_witness(),'database_data_sha256':self.data_witness()}
                sealed_write(folder/'checkpoint.json',cp);self.stage(j,'CHECKPOINT_WRITTEN',checkpoint=j['id'])
            finally:self.resume_verified(j,j['before']['risk'],False)
            self.finish(j,checkpoint=j['id']);return cp
    def load_checkpoint(self,ident,verified=False):
        r.need(type(ident) is str and re.fullmatch('[0-9a-f]{32}',ident) is not None,'CHECKPOINT_ID')
        cp=sealed_read(PRIVATE/'checkpoints'/ident/'checkpoint.json')
        r.need(cp['project']==LANE and cp['manifest']==self.digest,'CHECKPOINT_SCOPE')
        if verified:r.need(cp['restore_verified'] and time.time()-cp['created']<1800,'CHECKPOINT_NOT_VERIFIED_OR_STALE')
        for label,digest in cp['files'].items():r.need(r.sha_file(PRIVATE/'checkpoints'/ident/(label+'.aesgcm'))==digest,'CHECKPOINT_CORRUPT')
        return cp
    def unseal(self,cp,label):
        blob=(PRIVATE/'checkpoints'/cp['id']/(label+'.aesgcm')).read_bytes();key=(PRIVATE/'keys'/(cp['id']+'.key')).read_bytes()
        return AESGCM(key).decrypt(blob[:12],blob[12:],canonical({'project':LANE,'manifest':self.digest,'label':label}))
    def create_new(self,j):
        # Reuse a previously verified stopped candidate with its original,
        # authenticated creation journal. Never rewrite its provenance labels.
        for row in sorted(self.d.rows(),key=lambda z:z['Name']):
            labels=row['Config'].get('Labels') or {};origin=labels.get('io.zerotrust.operation','')
            if labels.get('io.zerotrust.promotion.manifest')!=self.digest or row['State']['Running']:continue
            if not re.fullmatch('[0-9a-f]{32}',origin) or not self.journal(origin).is_file():continue
            prior=sealed_read(self.journal(origin))
            if prior['status']!='DONE' or prior['operation']!='apply' or prior.get('new_id')!=row['Id'] or prior['manifest']!=self.digest:continue
            name=row['Name'].lstrip('/');self.verify_new(name,origin)
            self.stage(j,'NEW_CREATED',new_name=name,new_id=row['Id'],container_operation=origin,reused_candidate=True)
            return name
        name=LANE+'-phase23a-risk-'+j['id'][:12];self.stage(j,'WILL_CREATE_NEW',new_name=name)
        r.need(not any(x['Name']=='/'+name for x in self.d.rows()),'NEW_NAME_EXISTS')
        args=['docker','create','--name',name,'--label','io.zerotrust.scope='+LANE,'--label','io.zerotrust.role=risk',
            '--label','io.zerotrust.promotion.manifest='+self.digest,'--label','io.zerotrust.operation='+j['id'],
            '--network',CORE,'--network-alias','risk','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges',
            '--read-only','--tmpfs','/tmp:mode=1777','--memory','640m','--restart','unless-stopped',
            '--env','SPRING_APPLICATION_JSON='+json.dumps(r.GEO),'--mount',f'type=volume,source={LANE}_risk-config,target=/run/demo,readonly',
            '--mount',f'type=bind,source={r.local_path(r.ROOT,self.m["geoip"]["directory"])},target=/geoip,readonly',r.NEW]
        ident=self.d.raw(*args).decode().strip();self.stage(j,'NEW_CREATED',new_id=ident);self.verify_new(name);return name
    def verify_runtime(self,name,smoke=False,internal=False):
        self.d.health(name,self.d.inspect(name)['Image']==r.NEW);self.v5()
        if smoke:self.smoke(('internal-' if internal else '')+('promoted' if self.d.inspect(name)['Image']==r.NEW else 'baseline'))
    def apply(self,envelope):
        with ProjectLock():
            r.need(self.state()['mode']=='BASELINE','APPLY_REQUIRES_KNOWN_BASELINE')
            j=self.new_operation(envelope,'apply');cp=self.load_checkpoint(j['request']['checkpoint'],True)
            self.validate(require_healthy=True);self.quiesce(j)
            self.d.start(self.name('keycloak'));self.d.health(self.name('keycloak'))
            self.stage(j,'OLD_STOPPED');name=self.create_new(j);self.d.start(name);self.d.health(name,True)
            self.stage(j,'NEW_STARTED')
            self.maintenance.start_internal(j,name)
            self.verify_runtime(name,True,internal=True);self.maintenance.verified(j)
            self.save_state({'mode':'PROMOTED','risk':name,'manifest':self.digest,'operation':j['id'],'checkpoint':cp['id'],
                'running_intent':j['running_before']})
            self.stage(j,'COMMITTED');self.maintenance.resume(j,name);self.finish(j);return self.state()
    def rollback(self,envelope):
        with ProjectLock():
            r.need(self.state()['mode']=='PROMOTED','ROLLBACK_REQUIRES_KNOWN_PROMOTED_STATE')
            j=self.new_operation(envelope,'rollback');self.quiesce(j)
            old=self.name('risk');self.maintenance.start_internal(j,old);self.stage(j,'ROLLBACK_OLD_STARTED')
            self.verify_runtime(old,True,internal=True);self.maintenance.verified(j)
            self.save_state({'mode':'BASELINE','risk':old,'manifest':self.digest,'operation':j['id'],'running_intent':j['running_before']})
            self.stage(j,'COMMITTED');self.maintenance.resume(j,old);self.finish(j);return self.state()
    def restart(self,envelope):
        with ProjectLock():
            j=self.new_operation(envelope,'restart');risk=self.current()
            if not any(j['running_before'].values()):
                j['running_before']=self.state().get('running_intent',dict.fromkeys(SERVICES,True))
            for s in STOP_ORDER:self.d.stop(risk if s=='risk' else self.name(s))
            self.stage(j,'STOPPED_FOR_RESTART');self.resume_verified(j,risk)
            self.save_state({**self.state(),'running_intent':j['running_before']});self.finish(j);return self.state()
    def stop(self,envelope):
        with ProjectLock():
            j=self.new_operation(envelope,'stop')
            if any(j['running_before'].values()):self.save_state({**self.state(),'running_intent':j['running_before']})
            for s in STOP_ORDER:self.d.stop(self.current() if s=='risk' else self.name(s))
            self.finish(j);return self.state()
    def recover_rollback(self,target,desired):
        before=target['before'];current=self.state()
        committed=current['mode']=='BASELINE' and current.get('operation')==target['id']
        r.need(before['mode']=='PROMOTED' and (current==before or committed),'ROLLBACK_RECOVERY_STATE_DRIFT')
        r.need(desired in ('BASELINE','PROMOTED'),'RECOVERY_TARGET_REQUIRED')
        r.need(not committed or desired=='BASELINE','COMMITTED_ROLLBACK_REQUIRES_NEW_APPLY')
        old=self.name('risk');promoted=before['risk'];self.verify_new(promoted)
        # Either finish the original rollback, or explicitly return to its
        # verified pre-operation image. Both use CURRENT storage, never restore.
        if desired=='BASELINE':
            self.d.stop(promoted);name=old
        else:
            self.d.stop(old);name=promoted
        self.quiesce(target)
        self.maintenance.start_internal(target,name);self.verify_runtime(name,True,internal=True)
        self.maintenance.verified(target)
        if desired=='BASELINE':self.save_state({'mode':'BASELINE','risk':old,'manifest':self.digest,'operation':target['id'],
            'running_intent':target['running_before']})
        self.stage(target,'RECOVERY_STATE_VERIFIED');self.maintenance.resume(target,name)
    def recover(self,envelope):
        with ProjectLock():
            j=self.new_operation(envelope,'recover');target=sealed_read(self.journal(j['request']['recover_of']))
            r.need(target['manifest']==self.digest,'RECOVERY_MANIFEST')
            if target['status']=='DONE':self.finish(j,no_op=True);return self.state()
            if j['request']['recover_target']=='STOPPED':
                r.need(target['operation'] in ('backup-only','restart','stop'),'STOPPED_RECOVERY_OPERATION_SCOPE')
                for service in STOP_ORDER:self.maintenance.stop(service)
                self.stage(target,'RECOVERY_HELD_STOPPED',status='DONE',recovered_by=j['id'],
                    original_running_intent_retained=True,explicit_stopped_recovery=True)
                self.finish(j);return self.state()
            if target['operation']=='backup-only':
                self.quiesce(target,True);self.resume_verified(target,target['before']['risk'],False)
            elif target['operation']=='restore-verify':
                for x in self.d.rows():
                    if (x['Config'].get('Labels') or {}).get('io.zerotrust.restore')==target['id']:
                        self.d.stop(x['Name'].lstrip('/'))
            elif target['operation'] in ('restart','stop'):
                r.need(self.state()['mode']==target['before']['mode'] and self.current()==target['before']['risk'],'RECOVERY_SELECTED_STATE_DRIFT')
                if target['operation']=='restart':
                    self.quiesce(target);self.resume_verified(target,self.current())
                else:
                    for s in STOP_ORDER:self.d.stop(self.current() if s=='risk' else self.name(s))
            elif target['operation']=='rollback':
                self.recover_rollback(target,j['request']['recover_target'])
            else:
                desired=j['request']['recover_target'];r.need(desired in ('BASELINE','PROMOTED'),'RECOVERY_TARGET_REQUIRED')
                if desired=='PROMOTED':
                    r.need(self.state()['mode']=='PROMOTED' and self.state()['operation']==target['id'],'PROMOTED_COMMIT_NOT_DURABLE')
                    name=self.current();self.verify_new(name)
                else:
                    r.need(self.state()['mode']!='PROMOTED' or self.state().get('operation')!=target['id'],'COMMITTED_PROMOTION_REQUIRES_EXPLICIT_ROLLBACK')
                    if target.get('new_name') and any(x['Name']=='/'+target['new_name'] for x in self.d.rows()):
                        self.verify_new(target['new_name'],target.get('container_operation',target['id']));self.d.stop(target['new_name'])
                    name=target['before']['risk'];self.save_state(target['before'])
                self.quiesce(target);self.resume_verified(target,name)
            self.stage(target,'RECOVERED',status='DONE',recovered_by=j['id']);self.finish(j);return self.state()

    def smoke(self,mode):
        work=OUT/('fix-checks' if mode.startswith('internal-') else 'checks')/uuid.uuid4().hex;work.mkdir(parents=True)
        self.helper('smoke',['/tests/promotion_verify.py',mode],[
            f'type=bind,source={r.ROOT/(r.PREFIX+"phase2/restore/private")},target=/private,readonly',
            f'type=bind,source={r.HERE},target=/tests,readonly',f'type=bind,source={work},target=/results',
            f'type=bind,source={PRIVATE/"fixtures"},target=/fixtures'],
            network=CORE,entrypoint='/opt/tools/bin/python',memory='1g')
        result=r.json_bytes((work/'result.json').read_bytes());r.need(result['status']=='PASS','TARGETED_SMOKE_FAILED')
        return result

    def table_witness(self,name=None):
        name=name or self.name('mysql');result={}
        for table,order in [('school.users','id'),('school.students','id'),('school.scores','id'),('keycloak.REALM','ID'),
            ('keycloak.USER_ENTITY','ID'),('keycloak.CREDENTIAL','ID'),('keycloak.COMPONENT','ID'),('keycloak.COMPONENT_CONFIG','ID'),
            ('keycloak.AUTHENTICATION_FLOW','ID'),('keycloak.AUTHENTICATION_EXECUTION','ID'),
            ('risk.subject_device_trust','subject_id'),('risk.known_devices','id'),('risk.device_trust_revocations','operation_id'),
            ('risk.authentication_success_events','id'),('risk.flyway_schema_history','installed_rank')]:
            result[table]=r.sha(self.d.sql(name,'SELECT * FROM pd_staging_'+table+' ORDER BY '+order))
        return result

    def data_witness(self,name=None):
        name=name or self.name('mysql');self.d.owned(name)
        return {schema:r.sha(self.d.raw('docker','exec',name,'mysqldump','--defaults-extra-file=/fixture/root.cnf',
            '--no-create-info','--skip-triggers','--skip-comments','--skip-dump-date','--skip-add-locks','--skip-disable-keys',
            '--hex-blob','--order-by-primary','--set-gtid-purged=OFF','--no-tablespaces',schema))
            for schema in ('pd_staging_school','pd_staging_keycloak','pd_staging_risk')}

    def fresh_volume(self,name,operation):
        r.need(name.startswith(LANE+'_phase23restore_'),'RESTORE_VOLUME_SCOPE')
        existing=self.d.raw('docker','volume','ls','--format','{{.Name}}').decode().split()
        r.need(name not in existing,'RESTORE_DESTINATION_NOT_FRESH')
        self.d.raw('docker','volume','create','--label','io.zerotrust.scope='+LANE,'--label','io.zerotrust.restore='+operation,name)

    def write_fresh_volume(self,name,archive,operation):
        safe_archive(archive);v=self.d.volumes([name])[0]
        r.need((v.get('Labels') or {}).get('io.zerotrust.restore')==operation,'FOREIGN_RESTORE_VOLUME')
        existing=self.helper('check-empty',['-C','/data','-cf','-','.'],[f'type=volume,source={name},target=/data,readonly'])
        r.need(not safe_archive(existing),'RESTORE_DESTINATION_NOT_EMPTY')
        self.helper('restore-volume',['-C','/data','-xf','-'],[f'type=volume,source={name},target=/data'],data=archive)

    def clone_restore_service(self,service,name,volumes,operation,contract=None):
        scoped_name(name);r.need(name.startswith(LANE+'-phase23restore-'),'RESTORE_CONTAINER_SCOPE')
        original=self.d.owned(self.name(service));r.need(service in ('mysql','redis'),'RESTORE_SERVICE_SCOPE')
        if contract is not None:
            witness=self.m['services'][service]['witness'];cfg=contract['config']
            r.need(r.sha(json.dumps(sorted(cfg.get('Env') or [])).encode())==witness['environment_sha256']
                and r.sha(canonical(cfg.get('Entrypoint')))==witness['entrypoint_sha256']
                and r.sha(canonical(cfg.get('Cmd')))==witness['cmd_sha256'],'RESTORE_RUNTIME_CONTRACT_MISMATCH')
            original={'Image':witness['image'],'Config':cfg,'Mounts':witness['mounts']}
        r.need(not any(x['Name']=='/'+name for x in self.d.rows()),'RESTORE_CONTAINER_EXISTS')
        for mount in original['Mounts']:
            destination=volumes[mount['Name']]
            r.need(destination.startswith(LANE+'_phase23restore_'),'RESTORE_VOLUME_SCOPE')
            v=self.d.volumes([destination])[0]
            r.need((v.get('Labels') or {}).get('io.zerotrust.scope')==LANE and v['Labels'].get('io.zerotrust.restore')==operation,'RESTORE_VOLUME_OWNERSHIP')
        envfile=PRIVATE/'restore-env'/(operation+'-'+service+'.env')
        vals=original['Config']['Env'];r.need(all('\n' not in x and '\r' not in x for x in vals),'MULTILINE_ENV_REJECTED')
        atomic(envfile,('\n'.join(vals)+'\n').encode())
        args=['docker','create','--name',name,'--label','io.zerotrust.scope='+LANE,'--label','io.zerotrust.restore='+operation,
            '--network','none','--hostname',service,'--add-host',service+':127.0.0.1',
            '--memory','768m' if service=='mysql' else '128m','--env-file',str(envfile)]
        if original['Config'].get('User'):args+=['--user',original['Config']['User']]
        entry=original['Config'].get('Entrypoint') or []
        if entry:args+=['--entrypoint',entry[0]]
        for mount in original['Mounts']:
            args+=['--mount',f'type=volume,source={volumes[mount["Name"]]},target={mount["Destination"]}'+(',readonly' if not mount['RW'] else '')]
        health=original['Config'].get('Healthcheck',{}).get('Test',[])
        if health:
            import shlex
            cmd=health[1] if health[0]=='CMD-SHELL' else shlex.join(health[1:])
            args+=['--health-cmd',cmd,'--health-interval','5s','--health-timeout','5s','--health-retries','36']
        args+=[original['Image'],*entry[1:],*(original['Config'].get('Cmd') or [])]
        self.d.raw(*args)

    def restore_verify(self,envelope):
        storage_guard()
        with ProjectLock():
            j=self.new_operation(envelope,'restore-verify');cp=self.load_checkpoint(j['request']['checkpoint'])
            r.need(cp.get('tables') is not None,'CHECKPOINT_TABLE_WITNESS_REQUIRED')
            prefix=LANE+'_phase23restore_'+j['id'][:10]+'_';volumes={};created=[]
            try:
                required=set(cp['configs'])|{LANE+'_mysql-data',LANE+'_redis-data'}
                for old in sorted(required):
                    name=prefix+old.removeprefix(LANE+'_');self.fresh_volume(name,j['id']);volumes[old]=name
                for old,label in cp['configs'].items():
                    archive=self.unseal(cp,label);self.write_fresh_volume(volumes[old],archive,j['id'])
                    r.need(safe_archive(self.read_volume(volumes[old]))==safe_archive(archive),'RESTORED_CONFIG_BYTES_MISMATCH')
                redis=self.unseal(cp,'redis');self.write_fresh_volume(volumes[LANE+'_redis-data'],redis,j['id'])
                r.need(safe_archive(self.read_volume(volumes[LANE+'_redis-data']))==safe_archive(redis),'REDIS_RESTORE_BYTES_MISMATCH')
                for service in ('mysql','redis'):
                    name=LANE+'-phase23restore-'+service+'-'+j['id'][:10]
                    contract=r.json_bytes(self.unseal(cp,'runtime-contract'))[service] if 'runtime-contract' in cp['files'] else None
                    self.clone_restore_service(service,name,volumes,j['id'],contract);created.append(name);self.d.start(name);self.d.health(name)
                mysql=created[0];x=self.d.owned(mysql)
                r.need(x['Config']['Labels'].get('io.zerotrust.restore')==j['id'] and
                    next(z for z in x['Mounts'] if z['Destination']=='/var/lib/mysql')['Name']==volumes[LANE+'_mysql-data'],'RESTORE_IMPORT_TARGET')
                self.d.raw('docker','exec','-i',mysql,'mysql','--defaults-extra-file=/fixture/root.cnf','--binary-mode',
                    data=self.unseal(cp,'sql'),timeout=120)
                actual=self.table_witness(mysql);r.need(actual==cp['tables'],'RESTORED_TABLE_WITNESS_MISMATCH');self.v5(mysql)
                r.need(self.data_witness(mysql)==cp['database_data_sha256'],'RESTORED_ALL_SCHEMA_DATA_MISMATCH')
                cp.update(restore_verified=True,restore_verified_at=time.time(),restore_operation=j['id'],restore_tables=actual,
                    redis_restore='exact archive member hashes before boot + healthy TLS Redis after boot',restore_containers=created,restore_volumes=volumes,
                    config_volumes_verified=len(cp['configs']),runtime_contract_restored='runtime-contract' in cp['files'])
                sealed_write(PRIVATE/'checkpoints'/cp['id']/'checkpoint.json',cp)
                self.stage(j,'RESTORE_VERIFIED',checkpoint=cp['id']);self.finish(j);return {'status':'PASS','tables':len(actual),'checkpoint':cp['id']}
            finally:
                for name in reversed(created):self.d.stop(name)


def dispatch(action,path,request=None):
    e=Executor(path)
    if action in ('plan','validate','status'):
        result=e.validate();result['state']=e.state();result['scope']='DISPOSABLE_REHEARSAL_ONLY';return result
    r.need(request is not None,'SIGNED_SCOPED_REQUEST_REQUIRED')
    envelope=r.json_bytes(Path(request).read_bytes())
    method={'backup-only':e.backup,'restore-verify':e.restore_verify,'apply':e.apply,'rollback':e.rollback,'restart':e.restart,'stop':e.stop,'recover':e.recover}.get(action)
    r.need(method is not None,'UNKNOWN_EXECUTION_OPERATION');return method(envelope)
