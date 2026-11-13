"""Independent D10 maintenance executor. No Network-v2 controller or owner signing key.

Live mutations require a plan-bound explicit owner GO receipt. Preparation/read-only
preflight never calls this executor. Rehearsal is restricted to its disposable namespace.
"""
import base64,contextlib,ctypes,datetime,hashlib,io,json,os,re,secrets,shlex,subprocess,sys,tarfile,time,uuid
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
ROOT=Path(__file__).resolve().parents[3]
LIVE='zt-full-function-20261111b';REHEARSAL='zt-d10-rollout-rehearsal-20261113';REHEARSAL_FINAL=REHEARSAL+'-final';REHEARSAL_FINAL2=REHEARSAL+'-final2'
class Blocked(RuntimeError):pass
def need(ok,message):
    if not ok:raise Blocked(message)
def sha(data):return hashlib.sha256(data).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def run(*args,data=None,env=None,timeout=180):
    result=subprocess.run(args,cwd=ROOT,input=data,capture_output=True,env=env,timeout=timeout)
    need(result.returncode==0,'COMMAND_FAILED_'+args[0]);return result.stdout
def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);temp=path.with_suffix(path.suffix+'.tmp');temp.write_bytes(canonical(value)+b'\n')
    # Windows refuses rename while a reader (acceptance helper bind mount) holds the target open.
    for attempt in range(200):
        try:temp.replace(path);return
        except PermissionError:
            if attempt==199:raise
            time.sleep(.05)
class Blob(ctypes.Structure):_fields_=[('size',ctypes.c_ulong),('data',ctypes.POINTER(ctypes.c_ubyte))]
def dpapi(data,entropy,decrypt=False):
    """Only NEW D10 backup keys; never opens an owner signing credential."""
    need(os.name=='nt','DPAPI_WINDOWS_REQUIRED')
    def blob(value):
        buf=ctypes.create_string_buffer(value);return Blob(len(value),ctypes.cast(buf,ctypes.POINTER(ctypes.c_ubyte))),buf
    source,keep=blob(data);salt,keep2=blob(entropy);out=Blob()
    fn=ctypes.windll.crypt32.CryptUnprotectData if decrypt else ctypes.windll.crypt32.CryptProtectData
    args=(ctypes.byref(source),None,ctypes.byref(salt),None,None,1,ctypes.byref(out))
    need(fn(*args)!=0,'D10_DPAPI_FAILED')
    try:return ctypes.string_at(out.data,out.size)
    finally:ctypes.windll.kernel32.LocalFree(out.data)
def secure_directory(path):
    path.mkdir(parents=True,exist_ok=True)
    if os.name=='nt':
        user=run('whoami').decode().strip();run('icacls',str(path),'/inheritance:r','/grant:r',user+':(OI)(CI)F')
    else:path.chmod(0o700)
def inspect(name):
    # Used in memory for cloning service configuration. Never serialize Env or command secrets.
    return json.loads(run('docker','inspect',name))[0]
def projection(name):
    x=inspect(name);return {'id':x['Id'],'name':x['Name'],'image':x['Image'],'running':x['State']['Running'],'started':x['State']['StartedAt'],'restarts':x['RestartCount']}
def launch_hash(x):return sha(canonical({'config':{k:x['Config'].get(k) for k in ('Entrypoint','Cmd','Env','User','WorkingDir','Healthcheck')},'host':x['HostConfig']}))
def migrate_config_hashes(volume,image):
    need(volume==LIVE+'_migrate-config','MIGRATOR_CONFIG_SCOPE')
    # Config files are not root-readable without DAC bypass; grant read/search only, never write.
    result=run('docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--cap-add','DAC_READ_SEARCH','--security-opt','no-new-privileges:true','--mount','type=volume,source='+volume+',target=/in,readonly','--entrypoint','sha256sum',image,'/in/migration.properties','/in/jvm.args','/in/trust.p12')
    return {line.split()[1]:line.split()[0] for line in result.decode().splitlines()}
class Checkpoint:
    def __init__(self,folder,plan_hash,create=False):
        self.folder=Path(folder);self.aad=plan_hash.encode();self.private=self.folder/'key-private'
        secure_directory(self.private);self.keyfile=self.private/'backup-key.dpapi'
        if create:
            need(not self.keyfile.exists(),'CHECKPOINT_KEY_ALREADY_EXISTS');self.keyfile.write_bytes(dpapi(AESGCM.generate_key(256),self.aad))
        need(self.keyfile.exists(),'CHECKPOINT_KEY_MISSING');self.cipher=AESGCM(dpapi(self.keyfile.read_bytes(),self.aad,True))
    def seal(self,name,data):
        need(name.replace('-','').isalnum(),'CHECKPOINT_NAME');nonce=os.urandom(12);path=self.folder/(name+'.aesgcm');need(not path.exists(),'CHECKPOINT_IMMUTABLE')
        path.write_bytes(nonce+self.cipher.encrypt(nonce,data,self.aad+b':'+name.encode()));return {'sha256':sha(path.read_bytes()),'bytes':path.stat().st_size}
    def unseal(self,name):
        data=(self.folder/(name+'.aesgcm')).read_bytes();return self.cipher.decrypt(data[:12],data[12:],self.aad+b':'+name.encode())
class Executor:
    def __init__(self,plan,mode,approval=None):
        self.plan=plan;self.mode=mode;self.project=plan['project'];self.id=plan['run_id'];self.hash=sha(canonical(plan))
        need(mode in ('live','rehearsal'),'UNKNOWN_EXECUTION_MODE')
        need((mode=='live' and self.project==LIVE) or (mode=='rehearsal' and self.project in (REHEARSAL,REHEARSAL_FINAL,REHEARSAL_FINAL2)),'PROJECT_SCOPE')
        need(self.id.isalnum() and len(self.id)==16,'RUN_ID')
        self.out=ROOT/plan['output'];need(self.out.resolve().is_relative_to((ROOT/'target').resolve()),'OUTPUT_SCOPE');self.out.mkdir(parents=True,exist_ok=True)
        self.state=self.out/'journal.json';self.j=json.loads(self.state.read_text()) if self.state.exists() else {'plan_hash':self.hash,'phase':'PREPARED','completed':[],'created':{}}
        need(self.j['plan_hash']==self.hash,'PLAN_DRIFT')
        if mode=='live':self.authorize(approval)
        if mode=='live':
            need(plan.get('executor_files') and plan.get('rehearsal_status')=='PASS','REVIEWED_EXECUTOR_REQUIRED')
            for path,digest in plan['executor_files'].items():
                file=(ROOT/path).resolve();need(file.is_relative_to(ROOT) and sha(file.read_bytes())==digest,'REVIEWED_CODE_DRIFT')
        self.old={r:row['name'].lstrip('/') for r,row in plan['source'].items()}
        self.allowed=set(self.old.values())|{self.name(r) for r in ('maintenance','private-ingress','public-ingress','risk','keycloak','backend','gateway','frontend','bootstrap','migrate','helper','acceptance-helper','restore-mysql','restore-helper')}
    def authorize(self,approval):
        need(approval is not None,'EXPLICIT_OWNER_GO_REQUIRED');a=json.loads(Path(approval).read_text())
        need(a.get('type')=='D10_EXPLICIT_OWNER_GO' and a.get('plan_sha256')==self.hash and a.get('nonce')==self.plan['approval_nonce'],'OWNER_GO_NOT_PLAN_BOUND')
        required=('controlled_deployment','maintenance','force_fresh_login','temporary_fail_closed','designated_test_accounts','preserve_existing_pending')
        need(all(a.get(k)is True for k in required),'OWNER_GO_SCOPE_INCOMPLETE')
        need(a.get('owner_message_sha256'),'OWNER_GO_EXPIRED_OR_MISSING_PROVENANCE')
        # Owner authorization persists; enforce an expiry only when the owner supplied one.
        if a.get('expires_utc'):
            try:expires=datetime.datetime.fromisoformat(a['expires_utc'])
            except ValueError:raise Blocked('OWNER_GO_EXPIRED_OR_MISSING_PROVENANCE')
            need(expires.tzinfo is not None and datetime.datetime.now(datetime.timezone.utc)<expires,'OWNER_GO_EXPIRED_OR_MISSING_PROVENANCE')
    @contextlib.contextmanager
    def exclusive(self):
        path=ROOT/'target/d10-phase3-locks'/(self.project+'.lock');path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('a+b') as f:
            f.seek(0);f.write(b'1');f.flush();f.seek(0)
            if os.name=='nt':
                import msvcrt
                try:msvcrt.locking(f.fileno(),msvcrt.LK_NBLCK,1)
                except OSError:raise Blocked('ANOTHER_D10_EXECUTOR_RUNNING')
                try:yield
                finally:f.seek(0);msvcrt.locking(f.fileno(),msvcrt.LK_UNLCK,1)
            else:
                import fcntl
                try:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except OSError:raise Blocked('ANOTHER_D10_EXECUTOR_RUNNING')
                try:yield
                finally:fcntl.flock(f,fcntl.LOCK_UN)
    def name(self,role):return self.project+'-d10-'+role+'-'+self.id
    def record(self,phase,detail=None):
        self.j['phase']=phase;self.j['updated_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        if detail:self.j.setdefault('evidence',{})[phase]=detail
        write(self.state,self.j)
    def scope(self,name):
        need(name in self.allowed,'FOREIGN_CONTAINER')
        if name in self.old.values():need(inspect(name)['Id']==next(x['id'] for x in self.plan['source'].values() if x['name'].lstrip('/')==name),'SOURCE_CONTAINER_DRIFT')
        else:
            labels=inspect(name)['Config']['Labels'] or {};need(labels.get('io.zerotrust.d10.run')==self.id and labels.get('io.zerotrust.d10.project')==self.project,'UNOWNED_D10_CONTAINER')
    def stop(self,*names):
        for name in names:self.scope(name)
        run('docker','stop','--time','25',*names,timeout=180)
        need(all(not inspect(n)['State']['Running'] for n in names),'WRITER_NOT_STOPPED')
    def sql(self,statement,container=None,data=None):
        name=container or self.old['mysql'];self.scope(name)
        return run('docker','exec','-i',name,'mysql','--defaults-extra-file=/fixture/root.cnf','-Nse',statement,data=data).decode().strip()
    def assert_source(self):
        for role,row in self.plan['source'].items():
            current=projection(self.old[role]);need(all(current[k]==row[k] for k in ('id','image','running','started','restarts')),'SOURCE_INVENTORY_DRIFT_'+role)
            if row.get('launch_sha256'):need(launch_hash(inspect(self.old[role]))==row['launch_sha256'],'SOURCE_LAUNCH_DRIFT_'+role)
        need(self.sql('SELECT COUNT(*) FROM pd_staging_risk.subject_device_trust WHERE pending_operation_id IS NOT NULL')==str(self.plan['pending_count']),'PENDING_SET_CHANGED')
        self.assert_trust_preserved()
        for role,files in self.plan['configuration_hashes'].items():
            for file,digest in files.items():need(run('docker','exec',self.old[role],'sha256sum',file).decode().split()[0]==digest,'LIVE_CONFIG_DRIFT')
        if self.mode=='live':need(migrate_config_hashes(self.plan['config_volumes']['migrate'],self.plan['utility_image'])==self.plan['migrate_configuration_hashes'],'MIGRATOR_CONFIG_DRIFT')
    def assert_trust_preserved(self):
        if self.plan.get('trust_rows')is not None:
            rows=json.loads(self.sql("SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT('subject',subject_id,'generation',generation,'pending',pending_operation_id)),JSON_ARRAY()) FROM pd_staging_risk.subject_device_trust"));expected={x['subject']:x for x in self.plan['trust_rows']};actual={x['subject']:x for x in rows};designated=set(self.j.get('designated_ids',self.plan.get('designated_ids',[])))
            need(all(actual.get(k)==value for k,value in expected.items()) and set(actual)-set(expected)<=designated,'TRUST_STATE_CHANGED')
        else:need(sha(self.sql('SELECT subject_id,generation,COALESCE(pending_operation_id,\'\') FROM pd_staging_risk.subject_device_trust ORDER BY subject_id').encode())==self.plan['trust_state_sha256'],'TRUST_STATE_CHANGED')
    def quiesce(self):
        need(self.j['phase'] in ('PREPARED','CLOSING'),'QUIESCE_STAGE')
        if self.j['phase']=='PREPARED':self.assert_source();self.record('CLOSING')
        self.stop(*(self.old[r] for r in ('ingress','gateway','backend','keycloak','risk','frontend','redis')))
        need(self.sql('SELECT COUNT(*) FROM information_schema.innodb_trx')=='0','IN_FLIGHT_DATABASE_TRANSACTION')
        need(self.sql('SELECT COUNT(*) FROM pd_staging_risk.subject_device_trust WHERE pending_operation_id IS NOT NULL')==str(self.plan['pending_count']),'PENDING_CHANGED_DURING_QUIESCE')
        self.record('QUIESCED',{'writers_stopped':True,'protected_ports':'source ingress + API/identity writers stopped; no gate opened'})
    def archive_volume(self,volume):
        need(volume in self.plan['source_volumes'],'FOREIGN_VOLUME')
        return run('docker','run','--rm','--name',self.name('helper'),'--network','none','--read-only','--label','io.zerotrust.d10.run='+self.id,'--label','io.zerotrust.d10.project='+self.project,'--mount','type=volume,source='+volume+',target=/in,readonly','--entrypoint','tar',self.plan['utility_image'],'-C','/in','-cf','-','.',timeout=90)
    def checkpoint(self):
        need(self.j['phase']=='QUIESCED','CHECKPOINT_REQUIRES_QUIESCENCE');folder=self.out/'checkpoint';cp=Checkpoint(folder,self.hash,not (folder/'key-private/backup-key.dpapi').exists())
        def seal(name,data):
            path=folder/(name+'.aesgcm')
            if path.exists():need(sha(cp.unseal(name))==sha(data),'QUIESCED_CHECKPOINT_CONTENT_DRIFT');return {'sha256':sha(path.read_bytes()),'bytes':path.stat().st_size}
            return cp.seal(name,data)
        dump=self.dump_sql(self.old['mysql']);sealed={'sql':seal('sql',dump)}
        for n,volume in enumerate(self.plan['source_volumes']):sealed['volume-'+str(n)]=seal('volume-'+str(n),self.archive_volume(volume))
        self.record('CHECKPOINTED',{'encrypted':sealed,'cipher':'AES-256-GCM / plan-bound AAD','key':'new D10 CurrentUser DPAPI; ACL inheritance removed','sql_plaintext_sha256':sha(dump),'volume_index':self.plan['source_volumes'],'writers_stopped':True});return cp
    def dump_sql(self,name):
        self.scope(name)
        return run('docker','exec',name,'mysqldump','--defaults-extra-file=/fixture/root.cnf','--single-transaction','--set-gtid-purged=OFF','--no-tablespaces','--hex-blob','--skip-comments','--skip-dump-date','--order-by-primary','--add-drop-database','--databases','pd_staging_school','pd_staging_risk','pd_staging_keycloak',timeout=180)
    def volume(self,role):return self.project+'_d10_'+self.id+'_'+role
    def new_volume(self,role):
        name=self.volume(role);need(name not in self.plan['source_volumes'],'SOURCE_VOLUME_OVERWRITE')
        existing=run('docker','volume','ls','--format','{{.Name}}').decode().splitlines()
        if name in existing:
            labels=json.loads(run('docker','volume','inspect',name))[0].get('Labels') or {}
            need(labels.get('io.zerotrust.d10.run')==self.id and labels.get('io.zerotrust.d10.project')==self.project,'UNOWNED_EXISTING_D10_VOLUME');return name
        run('docker','volume','create','--label','io.zerotrust.d10.run='+self.id,'--label','io.zerotrust.d10.project='+self.project,name);return name
    def load_volume(self,volume,data):
        need(volume.startswith(self.project+'_d10_'+self.id+'_') and volume not in self.plan['source_volumes'],'FOREIGN_RESTORE_VOLUME')
        # tar is a directly archived owned volume; reject traversal/symlinks before extraction.
        with tarfile.open(fileobj=io.BytesIO(data)) as t:
            need(all(not Path(m.name).is_absolute() and '..' not in Path(m.name).parts and (m.isfile() or m.isdir()) for m in t.getmembers()),'UNSAFE_VOLUME_ARCHIVE')
        run('docker','run','--rm','-i','--name',self.name('helper'),'--network','none','--read-only','--label','io.zerotrust.d10.run='+self.id,'--label','io.zerotrust.d10.project='+self.project,'--mount','type=volume,source='+volume+',target=/out','--entrypoint','tar',self.plan['utility_image'],'-C','/out','-xf','-',data=data,timeout=90)
    def cloned_config(self,role,patch,output_role=None):
        source=self.plan['config_volumes'][role];cp=Checkpoint(self.out/'checkpoint',self.hash)
        data=cp.unseal('volume-'+str(self.plan['source_volumes'].index(source)))
        source_tar=tarfile.open(fileobj=io.BytesIO(data));output=io.BytesIO()
        with source_tar,tarfile.open(fileobj=output,mode='w') as target:
            changed=set()
            for m in source_tar.getmembers():
                path=m.name.removeprefix('./')
                if m.isfile():
                    raw=source_tar.extractfile(m).read()
                    if path in patch:raw=patch[path](raw);m.size=len(raw);changed.add(path)
                    target.addfile(m,io.BytesIO(raw))
                elif m.isdir():target.addfile(m)
                else:raise Blocked('UNSAFE_CONFIG_ARCHIVE')
            for path,fn in patch.items():
                if path not in changed:
                    raw=fn(b'');m=tarfile.TarInfo(path);m.size=len(raw);m.mode=0o400;m.uid=65532 if role=='keycloak' else 10001; m.gid=m.uid;target.addfile(m,io.BytesIO(raw))
        key=(output_role or role)+'-config';volume=self.new_volume(key);self.load_volume(volume,output.getvalue());self.j['created'][key]=volume;write(self.state,self.j);return volume
    def create_like(self,role,source_role,image,mounts,env_extra=None,command=None,network=None,aliases=None,ports=False,entrypoint=None,restart='unless-stopped',ip=None,extra_hosts=None):
        name=self.name(role);source=inspect(self.old[source_role]);network=network or self.plan['core_network']
        need(image in set(self.plan['candidate_images'].values())|{source['Image'],self.plan['utility_image']},'UNBOUND_IMAGE')
        args=['docker','create','--name',name,'--label','io.zerotrust.d10.run='+self.id,'--label','io.zerotrust.d10.project='+self.project,'--restart',restart,'--network',network]
        if ip:args+=['--ip',ip]
        for key,value in (extra_hosts or {}).items():args+=['--add-host',key+':'+value]
        for alias in aliases or []:args+=['--network-alias',alias]
        h=source['HostConfig'];config=source['Config'];environment=dict(item.split('=',1) for item in config.get('Env') or []);environment.update(env_extra or {})
        inherited=dict(os.environ);inherited.update(environment)
        for key in environment:args+=['--env',key]
        if config.get('User'):args+=['--user',config['User']]
        if h.get('Memory'):args+=['--memory',str(h['Memory'])]
        if h.get('MemorySwap') not in (None,0):args+=['--memory-swap',str(h['MemorySwap'])]
        if h.get('PidsLimit')is not None:args+=['--pids-limit',str(h['PidsLimit'])]
        if h.get('NanoCpus'):args+=['--cpus',str(h['NanoCpus']/1e9)]
        elif h.get('CpuQuota'):
            args+=['--cpu-quota',str(h['CpuQuota'])]
            if h.get('CpuPeriod'):args+=['--cpu-period',str(h['CpuPeriod'])]
        if h.get('CpusetCpus'):args+=['--cpuset-cpus',h['CpusetCpus']]
        for limit in h.get('Ulimits') or []:args+=['--ulimit',limit['Name']+'='+str(limit['Soft'])+':'+str(limit['Hard'])]
        if h.get('ReadonlyRootfs'):args+=['--read-only']
        for path,options in (h.get('Tmpfs') or {}).items():args+=['--tmpfs',path+':'+options]
        for cap in h.get('CapDrop') or []:args+=['--cap-drop',cap]
        for option in h.get('SecurityOpt') or []:args+=['--security-opt',option]
        if config.get('WorkingDir'):args+=['--workdir',config['WorkingDir']]
        health=config.get('Healthcheck')
        if health and role not in ('bootstrap','migrate','restore-mysql'):
            test=health.get('Test') or []
            if test and test[0]!='NONE':
                args+=['--health-cmd',test[1] if test[0]=='CMD-SHELL' else shlex.join(test[1:])]
                for key,flag in [('Interval','--health-interval'),('Timeout','--health-timeout'),('StartPeriod','--health-start-period')]:
                    if health.get(key):args+=[flag,str(health[key])+'ns']
                if health.get('Retries'):args+=['--health-retries',str(health['Retries'])]
        for source_mount,target,readonly in mounts:args+=['--mount','type='+('bind' if source_mount.startswith(('/',str(ROOT))) else 'volume')+',source='+source_mount+',target='+target+(',readonly' if readonly else '')]
        if ports:
            for port,bindings in (h.get('PortBindings') or {}).items():
                for binding in bindings:args+=['--publish',binding['HostIp']+':'+binding['HostPort']+':'+port]
        selected_entrypoint=entrypoint if entrypoint is not None else config.get('Entrypoint')
        if selected_entrypoint:args+=['--entrypoint',selected_entrypoint[0]]
        args+=[image]+((selected_entrypoint or [])[1:])+(command if command is not None else config.get('Cmd') or [])
        signature=sha(canonical({'argv':args,'environment':environment}))
        args[2:2]=['--label','io.zerotrust.d10.spec='+signature]
        existing=run('docker','ps','-aq','--filter','name=^/'+name+'$').decode().strip()
        if existing:
            self.scope(name);need((inspect(name)['Config']['Labels'] or {}).get('io.zerotrust.d10.spec')==signature,'CREATED_SPEC_DRIFT')
        else:run(*args,env=inherited)
        self.j['created'][role]=name;write(self.state,self.j);return name
    def start(self,name):
        need(name not in {self.old.get(role) for role in ('risk','keycloak','backend','gateway','frontend','ingress')},'OLD_V7_START_FORBIDDEN')
        self.scope(name);run('docker','start',name)
    def hold(self,reason):
        # Never starts old API/issuer pins or restores old state. Public maintenance stays closed.
        held_from=self.j['phase']
        for role in ('ingress','gateway','backend','keycloak','risk','frontend'):
            name=self.old[role]
            if inspect(name)['State']['Running']:self.stop(name)
        public=self.j['created'].get('public-ingress')
        if public and inspect(public)['State']['Running']:self.stop(public)
        maintenance=self.j['created'].get('maintenance')
        if maintenance and not inspect(maintenance)['State']['Running']:self.start(maintenance)
        self.record('HOLD_FAIL_CLOSED',{'reason':reason,'held_from':held_from,'security_rollback':False})
    def mark_acceptance(self,receipt):
        need(self.j['phase']=='GATES_PRIVATE','GATES_NOT_PRIVATE')
        need(receipt.get('status')=='PASS' and receipt.get('plan_sha256')==self.hash and receipt.get('images')==self.plan['candidate_images'],'NATIVE_ACCEPTANCE_NOT_BOUND')
        need(all(receipt.get(k)is True for k in ('strict_api','strict_issuer','legacy_denied','mfa_proof','reset_resume','rbac_ownership','tls_roles','B0_SHADOW','pending_preserved','performance')),'ACCEPTANCE_INCOMPLETE')
        write(self.out/'native-acceptance.json',receipt);self.record('ACCEPTED_PRIVATE',{'receipt_sha256':sha(canonical(receipt))})
    def assert_openable(self):
        need(self.j['phase']=='ACCEPTED_PRIVATE','HUMAN_TRAFFIC_MUST_REMAIN_CLOSED')
        receipt=json.loads((self.out/'native-acceptance.json').read_text());need(sha(canonical(receipt))==self.j['evidence']['ACCEPTED_PRIVATE']['receipt_sha256'],'ACCEPTANCE_RECEIPT_DRIFT')
        for role in ('risk','keycloak','backend','gateway','frontend'):
            name=self.j['created'][role];self.scope(name);x=inspect(name);need(x['State']['Running'] and x['Image']==self.plan['candidate_images'][role],'MISSING_OR_WRONG_GATE_'+role)
        need(self.sql('SELECT MAX(CAST(version AS UNSIGNED)) FROM pd_staging_risk.flyway_schema_history WHERE success=1')=='9','SCHEMA_GATE')
        need(self.sql('SELECT COUNT(*) FROM pd_staging_risk.subject_device_trust WHERE pending_operation_id IS NOT NULL')==str(self.plan['pending_count']),'PENDING_PRESERVATION_GATE')
        expected=self.j['evidence']['GATES_PRIVATE'].get('configuration_hashes')
        if expected is not None:need(self.configuration_fingerprints()==expected,'STRICT_CONFIGURATION_DRIFT')
        return True
    def configuration_fingerprints(self):
        result={}
        for role in ('risk','keycloak','backend','gateway'):
            root='/run/secrets' if role=='keycloak' else '/run/demo'
            files=['keycloak.conf','d10-security-secret'] if role=='keycloak' else ['application.properties','jvm.args']+(['d10-security-secret'] if role in ('backend','gateway') else [])
            result[role]={name:run('docker','exec',self.name(role),'sha256sum',root+'/'+name).decode().split()[0] for name in files}
        return result
    def maintenance(self):
        need(self.j['phase']=='CHECKPOINTED','MAINTENANCE_REQUIRES_CHECKPOINT')
        def closed(raw):
            text=raw.decode();need('server {' in text,'NGINX_SERVER_FORM_CHANGED')
            return text.replace('server {','server {\nadd_header Retry-After 60 always;\nadd_header Cache-Control no-store always;\nreturn 503;').encode()
        volume=self.cloned_config('ingress',{'nginx.conf':closed},'maintenance')
        name=self.create_like('maintenance','ingress',self.plan['source']['ingress']['image'],[(volume,'/run/demo',True)],network=self.plan['maintenance_network'],ports=self.mode=='live')
        self.start(name);self.record('MAINTENANCE',{'public':'all requests503 or transport closed; original API/identity writers remain stopped'})
    def verify_restore(self):
        need(self.j['phase']=='MAINTENANCE','RESTORE_REQUIRES_MAINTENANCE')
        cp=Checkpoint(self.out/'checkpoint',self.hash)
        volume=self.new_volume('restore-mysql-config');index=self.plan['source_volumes'].index(self.plan['config_volumes']['mysql']);self.load_volume(volume,cp.unseal('volume-'+str(index)))
        data=self.new_volume('restore-mysql-data')
        name=self.create_like('restore-mysql','mysql',self.plan['source']['mysql']['image'],[(volume,'/fixture',True),(data,'/var/lib/mysql',False)],network='none',ports=False,restart='no',extra_hosts={'mysql':'127.0.0.1'});self.start(name)
        plan_file=self.out/'execution-plan.json';write(plan_file,self.plan)
        result=run(sys.executable,str(Path(__file__).with_name('restore_worker.py')),str(plan_file),name,timeout=240)
        need(result.startswith(b'PASS '),'RESTORE_PROOF_MISSING');self.stop(name)
        self.record('RESTORE_VERIFIED',{'independent_process':True,'target':name,'network':'none','ports':0,'SQL':'exact INSERT bytes + canonical DDL; only redundant utf8mb4 declaration normalized','proof':'restore-proof.json','encryption':'AES-GCM tag/plan AAD; DPAPI key; no plaintext SQL file','source_stopped':True})
    def install_artifacts(self,credentials):
        need(self.j['phase']=='RESTORE_VERIFIED','INSTALL_BEFORE_RESTORE_VERIFICATION')
        contract=json.loads((Path(__file__).with_name('contract.json')).read_text())
        def append(values):return lambda raw:raw+b'\n'+b'\n'.join((k+'='+v).encode() for k,v in values.items())+b'\n'
        self.cloned_config('risk',{'application.properties':append({'risk.network-v2.mode':'SHADOW','risk.network-v2.retention-enabled':'false','risk.policy.model':'BASELINE_B0'})})
        self.cloned_config('keycloak',{'d10-security-secret':lambda _:credentials['zerotrust-issuer-security'].encode()})
        for role,client in [('backend','zerotrust-portal-security'),('gateway','zerotrust-gateway-security')]:
            properties=dict(contract['backend_gateway_properties']);properties['app.security.authority.client-id']=client
            self.cloned_config(role,{'application.properties':append(properties),'d10-security-secret':lambda _,client=client:credentials[client].encode()})
        self.cloned_config('migrate',{})
        migrate=self.create_like('migrate','risk',self.plan['candidate_images']['risk'],[(self.j['created']['migrate-config'],'/run/demo',True)],entrypoint=['java','@/run/demo/jvm.args','-cp','/app/unpacked/BOOT-INF/classes:/app/unpacked/BOOT-INF/lib/*:/app/tools','Migrate'],command=[],restart='no')
        self.start(migrate);need(run('docker','wait',migrate,timeout=180).strip()==b'0','ADDITIVE_MIGRATION_FAILED')
        need(self.sql('SELECT MAX(CAST(version AS UNSIGNED)) FROM pd_staging_risk.flyway_schema_history WHERE success=1')=='9','MIGRATION_NOT_V9')
        # Private candidate aliases replace stopped originals; never leave an old writer running.
        for role in ('risk','keycloak','backend','gateway','frontend','ingress'):
            source=inspect(self.old[role]);need(not source['State']['Running'],'OLD_WRITER_RUNNING')
            if self.plan['core_network'] in source['NetworkSettings']['Networks']:run('docker','network','disconnect',self.plan['core_network'],self.old[role])
        for role in ('risk','keycloak','backend','gateway','frontend'):
            source=inspect(self.old[role]);mounts=[]
            for m in source['Mounts']:
                if m['Type']=='volume' and m['Name']==self.plan['config_volumes'].get(role):mounts.append((self.j['created'][role+'-config'],m['Destination'],True))
                else:mounts.append((m.get('Name',m['Source']),m['Destination'],not m['RW']))
            options={}
            if role=='keycloak':options['env_extra']=contract['issuer_environment']
            if role=='frontend':
                image=json.loads(run('docker','image','inspect',self.plan['candidate_images'][role]))[0];options.update(entrypoint=image['Config'].get('Entrypoint') or [],command=image['Config'].get('Cmd') or [])
            self.create_like(role,role,self.plan['candidate_images'][role],mounts,aliases=[role],**options)
        self.record('ARTIFACTS_INSTALLED',{'schema':9,'old_writers':'stopped/disconnected','human_ingress':'maintenance','positive_authorization_cache':False})
    def bootstrap(self,credentials):
        need(self.j['phase']=='ARTIFACTS_INSTALLED','BOOTSTRAP_STAGE')
        env=json.loads((Path(__file__).with_name('contract.json')).read_text())['issuer_environment'];env['D10_BOOT_SECRET']=credentials['bootstrap_secret']
        name=self.create_like('bootstrap','keycloak',self.plan['candidate_images']['keycloak'],[(self.j['created']['keycloak-config'],'/run/secrets',True)],env_extra=env,command=['--config-file=/run/secrets/keycloak.conf','bootstrap-admin','service','--optimized','--no-prompt','--client-id',credentials['bootstrap_client'],'--client-secret:env','D10_BOOT_SECRET'],restart='no')
        self.start(name);need(run('docker','wait',name,timeout=150).strip()==b'0','NATIVE_BOOTSTRAP_FAILED')
        # Redis is optimization only; restart the exact same persistent source instance.
        self.start(self.old['redis']);self.start(self.name('keycloak'));self.start(self.name('risk'));self.record('ISSUER_AUTHORITY_STARTED')
    def start_api_private(self):
        need(self.j['phase']=='NATIVE_PROVISIONED','NATIVE_NOT_PROVISIONED')
        self.start(self.name('backend'));self.start(self.name('gateway'));self.start(self.name('frontend'))
        volume=self.cloned_config('ingress',{},'private-ingress')
        name=self.create_like('private-ingress','ingress',self.plan['source']['ingress']['image'],[(volume,'/run/demo',True)],aliases=['portal.full-function.test','auth.full-function.test'],ip=self.plan['ingress_core_ip'],ports=False)
        self.start(name);self.record('GATES_STARTING_PRIVATE',{'all_gate_images':self.plan['candidate_images'],'human_ports':'maintenance503; private acceptance ingress has no published port','configuration_hashes':self.configuration_fingerprints()})
    def open_public(self):
        self.assert_openable()
        private=self.name('private-ingress');self.stop(private);run('docker','network','disconnect',self.plan['core_network'],private)
        name=self.create_like('public-ingress','ingress',self.plan['source']['ingress']['image'],[(self.j['created']['private-ingress-config'],'/run/demo',True)],aliases=['portal.full-function.test','auth.full-function.test'],ip=self.plan['ingress_core_ip'],ports=self.mode=='live')
        for network,settings in inspect(self.old['ingress'])['NetworkSettings']['Networks'].items():
            if network!=self.plan['core_network']:
                args=['docker','network','connect']
                for alias in settings.get('Aliases') or []:
                    if alias in ('portal.full-function.test','auth.full-function.test'):args+=['--alias',alias]
                run(*args,network,name)
        self.record('OPENING_STRICT_ONLY');self.stop(self.name('maintenance'));self.start(name)
        self.record('OPEN_STRICT',{'legacy_V7_rollback':'FORBIDDEN','all_strict_gates_preverified':True,'security_state_restored':False})
