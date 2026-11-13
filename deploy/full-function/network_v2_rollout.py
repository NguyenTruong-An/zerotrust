"""Fixed active SHADOW binding. Default plan is read-only; every mutation needs a new owner signature.

Frozen Risk-only engine code is imported into a separate namespace, never edited.
Its AES-GCM checkpoint and independent-restore primitives are reused; coordinated
Risk/Keycloak/migration operations have their own descriptor, state and authorization.
"""
import argparse,base64,contextlib,contextvars,datetime as dt,hashlib,hmac,importlib.util,json,os,re,subprocess,sys,time,types,uuid
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import promotion_context as legacy
import risk_promotion as r
import network_v2_contract as contract

HERE=Path(__file__).resolve().parent
PROJECT='zt-full-function-20261111b';CORE=PROJECT+'_core'
PACKAGE=HERE/'network-v2-shadow'
DESCRIPTOR=PACKAGE/'execution.v3.json';PACKET=PACKAGE/'operation.PENDING.v3.json'
PRIVATE=r.ROOT/'target/full-function-20261111b/network-v2-shadow-v3-private'
OUT=r.ROOT/'target/full-function-20261111b/network-v2-shadow'
ANCHOR=(Path.home()/'.zerotrust-owner/network-v2-shadow-v3/anchor.json')
PREVIOUS_PRIVATE=r.ROOT/'target/full-function-20261111b/network-v2-shadow-private'
PREVIOUS_DESCRIPTOR=PACKAGE/'execution.v1.json';PREVIOUS_PACKET=PACKAGE/'operation.PENDING.json'
PREVIOUS_SHA='9ba6497a4bfdd404a9f9a7be13c99c896256c5f5443d822dcde7a14bd939d2de'
PREVIOUS_PACKET_SHA='789373fce6eef3f8b9fe11aebec1531ef73eccda6042dbfdb104134928fb1c47'
PARENT_PRIVATE=r.ROOT/'target/full-function-20261111b/network-v2-shadow-v2-private'
PARENT_DESCRIPTOR=PACKAGE/'execution.v2.json';PARENT_PACKET=PACKAGE/'operation.PENDING.v2.json'
PARENT_SHA='eebdfccaa8606b1b342e1c0ff0a082dbfc2803c388eed78fc1d6c9247a561477'
PARENT_PACKET_SHA='991c0886f31d7de1497c870e81de914d5b611466eb6ea8dde059b6d08876adbd'
OLD={'risk':'sha256:1ec3c4db626d6c232ca9a30c61188d69e883d40eb0005c29bd0d15921258686a',
     'keycloak':'sha256:29f942de9bfd6b2823d9922ebf13790bdb6519e0a70b3276a076324fe91b9085'}
NEW={'risk':'sha256:85a7e95acf33156571d4cc37d1e30c327d715b668bef65b4323e724b8a463fe7',
     'keycloak':'sha256:ec2b47104a9b85a2272689edd2cc009536f566595e1f7efa82fc1ae29f6c94df'}
OPERATIONS={'backup-only':'backup','restore-verify':'restore_verify','apply':'apply','rollback':'rollback','restart':'restart','recover':'recover'}
SERVICES=('mysql','redis','crl','keycloak','risk','backend','frontend','gateway','ingress')
WRITERS=('ingress','gateway','frontend','backend','risk','keycloak')
CHECKSUMS={'1':1185184692,'2':-1951422130,'3':481224608,'4':1302227479,'5':661092940,'6':1392077360,'7':-601621005}
LEDGER="SELECT version,checksum,success FROM pd_staging_risk.flyway_schema_history ORDER BY installed_rank"
CRITICAL=('subject_device_trust','known_devices','device_trust_revocations','authentication_success_events')
ISSUER='OWNER_EXPLICIT_NETWORK_V2_SHADOW_AUTHORIZATION'
SHADOW={'risk.network-v2.mode':'SHADOW','risk.network-v2.retention-enabled':False,'risk.network-v2.work-queue-capacity':128,
        'risk.network-v2.pending-capacity':4096,'risk.network-v2.pending-ttl':'PT10M','risk.network-v2.history-days':30,
        'risk.network-v2.history-limit':128,'risk.network-v2.minimum-samples':3,'risk.network-v2.minimum-distinct-days':2}
canonical=legacy.canonical
sha=r.sha
need=r.need

def payload(m,operation,checkpoint=None,recover_of=None,recover_target=None,now=None,ident=None):
    need(operation in OPERATIONS,'SHADOW_OPERATION_SCOPE');now=int(time.time()) if now is None else now
    return {'id':ident or uuid.uuid4().hex,'project':PROJECT,'operation':operation,'descriptor_sha256':r.sha_file(DESCRIPTOR),
        'packet_sha256':r.sha_file(PACKET),'release_sha256':sha(canonical(m['release'])),
        'checkpoint_rules_sha256':sha(canonical(m['checkpoint_rules'])),'maintenance':list(WRITERS),
        'checkpoint':checkpoint,'recover_of':recover_of,'recover_target':recover_target,
        'issued':now,'expires':now+600,'owner_sid':m['owner_sid'],'issuer':ISSUER}

def verify(envelope,m,descriptor_sha,packet_sha,operation,used,anchor,now=None):
    now=int(time.time()) if now is None else now
    need(type(envelope) is dict and set(envelope)=={'payload','signature'},'SHADOW_ENVELOPE_SHAPE')
    p=envelope['payload']
    fields={'id','project','operation','descriptor_sha256','packet_sha256','release_sha256','checkpoint_rules_sha256',
            'maintenance','checkpoint','recover_of','recover_target','issued','expires','owner_sid','issuer'}
    need(type(p) is dict and set(p)==fields,'SHADOW_REQUEST_SHAPE')
    need(type(p['id']) is str and re.fullmatch('[0-9a-f]{32}',p['id']),'SHADOW_REQUEST_ID')
    need(p['id'] not in used,'SHADOW_REQUEST_ALREADY_USED')
    need(type(p['issued']) is int and type(p['expires']) is int and p['issued']<=now+5 and now<p['expires']<=p['issued']+600,'SHADOW_REQUEST_EXPIRED')
    expected={'project':PROJECT,'operation':operation,'descriptor_sha256':descriptor_sha,'packet_sha256':packet_sha,
              'release_sha256':sha(canonical(m['release'])),'checkpoint_rules_sha256':sha(canonical(m['checkpoint_rules'])),
              'maintenance':list(WRITERS),'owner_sid':m['owner_sid'],'issuer':ISSUER}
    need(all(p.get(k)==value for k,value in expected.items()),'SHADOW_REQUEST_BINDING')
    need(anchor.get('kind')=='OWNER_CONTROLLED_NETWORK_V2_SHADOW_ONLY' and anchor.get('project')==PROJECT
         and anchor.get('owner_sid')==m['owner_sid'] and anchor.get('issuer')==ISSUER,'SHADOW_ANCHOR_SCOPE')
    need(anchor.get('descriptor_sha256')==descriptor_sha and anchor.get('packet_sha256')==packet_sha,'SHADOW_ANCHOR_BINDING')
    need(type(anchor.get('expires')) is int and now<anchor['expires'] and operation in anchor.get('operations',[]),'SHADOW_ANCHOR_EXPIRED_OR_OPERATION')
    if operation in ('apply','restore-verify'):
        need(type(p['checkpoint']) is str and re.fullmatch('[0-9a-f]{32}',p['checkpoint']),'SHADOW_CHECKPOINT_REQUIRED')
    else:need(p['checkpoint'] is None,'SHADOW_UNEXPECTED_CHECKPOINT')
    if operation=='recover':
        need(type(p['recover_of']) is str and re.fullmatch('[0-9a-f]{32}',p['recover_of']) and p['recover_target'] in ('BASELINE','SHADOW','STOPPED'),'SHADOW_RECOVERY_BINDING')
        if p['recover_target']=='BASELINE':need('rollback' in anchor.get('operations',[]),'SHADOW_RECOVERY_REQUIRES_ROLLBACK_SCOPE')
    else:need(p['recover_of'] is None and p['recover_target'] is None,'SHADOW_UNEXPECTED_RECOVERY')
    try:
        public=base64.b64decode(anchor['public_key'],validate=True)
        need(sha(public)==anchor['public_key_sha256'],'SHADOW_PUBLIC_KEY_HASH')
        Ed25519PublicKey.from_public_bytes(public).verify(base64.b64decode(envelope['signature'],validate=True),canonical(p))
    except Exception:raise r.Rejected('SHADOW_OWNER_SIGNATURE_INVALID') from None
    return p

def schema_state(text,allow_partial=False):
    rows=[line.split('\t') for line in text.strip().splitlines()]
    need(len(rows)>=5 and [row[0] for row in rows[:5]]==list('12345'),'SHADOW_BASE_SCHEMA')
    need(all(row[1:]==[str(CHECKSUMS[row[0]]),'1'] for row in rows[:5]),'SHADOW_V5_OR_BASE_CHECKSUM_DRIFT')
    extra=rows[5:]
    if allow_partial and extra and all(row[0] in ('6','7') for row in extra) and any(row[2]!='1' for row in extra):return 6
    need(all(len(row)==3 and row[0] in ('6','7') and row[1]==str(CHECKSUMS[row[0]]) and row[2]=='1' for row in extra),'SHADOW_PARTIAL_OR_UNKNOWN_MIGRATION')
    need([row[0] for row in extra] in ([],['6'],['6','7']),'SHADOW_MIGRATION_ORDER')
    return int(rows[-1][0])

def admit_writers(identifiers,selected,pending,role):
    need(len(identifiers)<=1,'SHADOW_DUPLICATE_'+role.upper()+'_WRITER')
    if not pending and identifiers:need(identifiers==[selected],'SHADOW_RUNNING_SELECTION_MISMATCH')

def predecessor_guard(m):
    """Freeze BOTH recovered bindings; never rewrite prior state, keys or journals."""
    expected=((PREVIOUS_SHA,PREVIOUS_PACKET_SHA,PREVIOUS_DESCRIPTOR,PREVIOUS_PACKET,PREVIOUS_PRIVATE),
              (PARENT_SHA,PARENT_PACKET_SHA,PARENT_DESCRIPTOR,PARENT_PACKET,PARENT_PRIVATE))
    need(set(m['predecessors'])=={PREVIOUS_SHA,PARENT_SHA},'SHADOW_PREDECESSOR_SET')
    for digest,packet_digest,desc,packet,private in expected:
        p=m['predecessors'][digest]
        need(p['packet_sha256']==packet_digest and r.sha_file(desc)==digest and r.sha_file(packet)==packet_digest,'SHADOW_PREDECESSOR_BINDING_DRIFT')
        observed={str(path.relative_to(r.ROOT)).replace('\\','/'):r.sha_file(path) for path in private.rglob('*') if path.is_file()}
        need(observed==p['control_files_sha256'],'SHADOW_PREDECESSOR_STATE_OR_JOURNAL_DRIFT')
        key=(private/'state.key').read_bytes()
        def read(path):
            value=r.json_bytes(path.read_bytes())
            need(hmac.compare_digest(value['mac'],hmac.digest(key,canonical(value['body']),'sha256').hex()),'SHADOW_PREDECESSOR_MAC_INVALID')
            return value['body']
        state=read(private/'state.json')
        need(state['manifest']==digest and state['mode']=='BASELINE'
             and all(state[role]==m['services'][role]['name'] for role in ('risk','keycloak')),'SHADOW_PREDECESSOR_NOT_BASELINE')
        need(all(read(path)['status']=='DONE' for path in (private/'journal').glob('*.json')),'SHADOW_PREDECESSOR_OPERATION_PENDING')


def descriptor():
    m=r.json_bytes(DESCRIPTOR.read_bytes());p=r.json_bytes(PACKET.read_bytes())
    need(m['kind']=='NETWORK_V2_ACTIVE_SHADOW_EXECUTION_NOT_AUTHORIZATION' and m['project']==PROJECT
         and m['approval_status']=='PENDING' and m['release']['old_images']==OLD and m['release']['new_images']==NEW,'SHADOW_DESCRIPTOR_IDENTITY')
    need(m['release']['keycloak_core']=='26.8.2' and m['release']['shadow']['risk.network-v2.mode']=='SHADOW'
         and m['release']['shadow']['risk.network-v2.retention-enabled'] is False,'SHADOW_POLICY_SCOPE')
    need(m['release']['shadow']==SHADOW and m['release']['risk_override']=={**r.GEO,**SHADOW},'SHADOW_NO_B0_OR_ENFORCEMENT_OVERRIDE')
    need(m['D10']=='UNRESOLVED' and m['D17']=='PENDING' and m['G8']=='INTERNET_NO_GO','SHADOW_RELEASE_GATES')
    need(m['binding_revision']==3 and p['binding_revision']==3
         and p['new_private_root']==str(PRIVATE.relative_to(r.ROOT)).replace('\\','/')
         and p['owner_anchor']==str(ANCHOR),'SHADOW_REBOUND_NAMESPACE')
    need(m['release']['initial_schema']==7 and m['release']['migration_mode']=='VALIDATE_V7_NO_DDL'
         and m['release']['environment_hash_algorithm']=='STRICT_JSON_CANONICAL_ENV_V1'
         and set(m['release']['candidate_contracts'])==set(NEW),'SHADOW_V3_CONTRACT_POLICY')
    need(m['checkpoint_rules']=={'maximum_age_seconds':1800,'independent_restore_required':True,'automatic_database_restore':False},'SHADOW_CHECKPOINT_RULES')
    need(p['descriptor_sha256']==r.sha_file(DESCRIPTOR) and p['approval_status']=='PENDING','SHADOW_PACKET_BINDING')
    need(m['owner_sid']==legacy.current_sid(),'SHADOW_WRONG_OWNER')
    need(r.ReadOnlyDocker().head()==m['review_HEAD'],'SHADOW_REVIEWED_HEAD_DRIFT')
    for name,digest in m['implementation_sha256'].items():need(r.sha_file(HERE/name)==digest,'SHADOW_IMPLEMENTATION_DRIFT')
    for name,digest in m['legacy_files_sha256'].items():need(r.sha_file(HERE/name)==digest,'SHADOW_LEGACY_CODE_DRIFT')
    for name,digest in m['source_sha256'].items():need(r.sha_file(r.local_path(r.ROOT,name))==digest,'SHADOW_SOURCE_DRIFT')
    for item in m['receipts']:need(r.sha_file(r.local_path(r.ROOT,item['path']))==item['sha256'],'SHADOW_EVIDENCE_DRIFT')
    predecessor_guard(m)
    return m

class Context:
    def __init__(self):
        self.m=descriptor();self.digest=r.sha_file(DESCRIPTOR);self.grant=contextvars.ContextVar('shadow_grant',default=False);self.selection=None;self.recovery_schema_allowed=False
        self.old=legacy.Context('active')
        need(r.sha_file(legacy.ACTIVE_PRIVATE/'state.json')==self.m['legacy_state_sha256'],'SHADOW_PRIOR_CONTROLLER_STATE_DRIFT')
        need(not self.old.engine.unfinished(),'SHADOW_OLD_OPERATION_PENDING')
        ident='_network_shadow_engine_'+uuid.uuid4().hex
        spec=importlib.util.spec_from_file_location(ident,HERE/'promotion_executor.py');module=importlib.util.module_from_spec(spec);sys.modules[ident]=module;spec.loader.exec_module(module)
        self.module=module
        module.LANE=PROJECT;module.CORE=CORE;module.PRIVATE=PRIVATE;module.OUT=OUT;module.MANIFEST=DESCRIPTOR
        module.r=types.SimpleNamespace(**{name:getattr(r,name) for name in dir(r) if not name.startswith('__')})
        module.r.OLD=OLD['risk'];module.r.NEW=NEW['risk'];module.r.GEO=self.m['release']['risk_override']
        module.authority=lambda:descriptor()
        module.verify_request=lambda envelope,m,digest,operation,used,now=None:self.authorize(envelope,operation,used,now)
        ctx=self;original=module.Docker
        class BoundDocker(original):
            def raw(self,*args,**kw):
                read=legacy.Context.read_command(args)
                if args[:2]==('docker','exec') and len(args)>5 and args[3]=='mysql':
                    sql=args[-1];read=sql.lstrip().startswith(('SELECT ','SHOW ')) and ';' not in sql and 'OUTFILE' not in sql.upper()
                if not read:ctx.require_grant()
                return super().raw(*args,**kw)
            def owned(self,name):
                row=self.inspect(name);labels=row['Config'].get('Labels') or {}
                need(name.startswith(PROJECT+'-') and labels.get('io.zerotrust.scope')==PROJECT,'SHADOW_FOREIGN_CONTAINER')
                baseline=next((rec for rec in ctx.m['services'].values() if rec['name']==name),None)
                if baseline:need(module.public_witness(row)==baseline['witness'],'SHADOW_BASE_CONTAINER_DRIFT')
                else:
                    need(not row['HostConfig'].get('PortBindings'),'SHADOW_PUBLISHED_REPLACEMENT')
                    if name.startswith(PROJECT+'-phase23restore-'):
                        need(re.fullmatch('[0-9a-f]{32}',labels.get('io.zerotrust.restore','')),'SHADOW_RESTORE_OWNERSHIP')
                    else:ctx.verify_replacement(row)
                return row
            def health(self,name,promoted=False,timeout=180):
                # Ownership is checked before selecting a probe. Both baseline and
                # candidate Risk containers use the custom TLS/CRL Java health tool.
                row=self.owned(name);labels=row['Config'].get('Labels') or {}
                is_risk=(name==ctx.m['services']['risk']['name'] or
                         (labels.get('io.zerotrust.role')=='risk' and
                          labels.get('io.zerotrust.shadow.manifest')==ctx.digest))
                try:return super().health(name,promoted=is_risk,timeout=timeout)
                except r.Rejected as error:
                    if str(error)=='OWNED_SERVICE_HEALTH_TIMEOUT':
                        service='risk' if is_risk else next((s for s,v in ctx.m['services'].items() if v['name']==name),'owned')
                        probe='custom-TLS-CRL' if is_risk else 'docker-healthcheck'
                        raise r.Rejected('OWNED_SERVICE_HEALTH_TIMEOUT service='+service+' probe='+probe+' timeout='+str(timeout)) from None
                    raise
        module.Docker=BoundDocker
        parent=module.Executor
        class Executor(parent):
            def save_state(self,value):ctx.require_grant();return super().save_state(value)
            def stage(self,*args,**kwargs):ctx.require_grant();return super().stage(*args,**kwargs)
            def new_operation(self,*args,**kwargs):ctx.require_grant();return super().new_operation(*args,**kwargs)
            def backup(self,envelope):
                ctx.require_grant()
                ident=envelope['payload']['id'];path=self.journal(ident);existed=path.exists()
                try:return super().backup(envelope)
                except Exception:
                    # Only close THIS newly admitted pre-mutation failure. Never
                    # repair an existing operation or hide incomplete checkpoint work.
                    if not existed and path.is_file():
                        j=module.sealed_read(path)
                        if (j['id']==ident and j['manifest']==ctx.digest and
                            j['operation']=='backup-only' and j['status']=='RUNNING' and
                            j['stage']=='AUTHORIZED' and
                            not (PRIVATE/'checkpoints'/ident).exists() and
                            not (PRIVATE/'keys'/(ident+'.key')).exists()):
                            self.finish(j,result='REJECTED_BEFORE_ACTIVE_MUTATION')
                    raise
            def restore_verify(self,envelope):ctx.require_grant();return super().restore_verify(envelope)
            def state(self):
                if not PRIVATE.exists():return ctx.initial_state()
                return super().state()
            def name(self,service):
                if service=='keycloak':return (ctx.selection or self.state()).get('keycloak',ctx.m['services']['keycloak']['name'])
                return ctx.m['services'][service]['name']
            def current(self):return (ctx.selection or self.state())['risk']
            def scope_check(self):ctx.require_grant()
            def validate(self,require_healthy=False):return ctx.validate(require_healthy)
            def verify_new(self,name,operation=None):return ctx.verify_replacement(self.d.inspect(name),operation)
            def verify_runtime(self,name,smoke=False,internal=False):ctx.verify_runtime()
            def smoke(self,mode):return ctx.verify_runtime()
            def quiesce(self,j,include_redis=False):ctx.quiesce(j,include_redis)
            def resume_verified(self,j,risk,smoke=True):ctx.resume(j,j['before'])
            def table_witness(self,name=None):
                result=super().table_witness(name)
                if ctx.schema(name or self.name('mysql'))>=6:
                    result['risk.network_authentication_contexts']=r.sha(self.d.sql(name or self.name('mysql'),'SELECT * FROM pd_staging_risk.network_authentication_contexts ORDER BY event_id'))
                return result
        self.executor=Executor(path=DESCRIPTOR)
        # Every inherited backup/restore utility now uses the new fixed namespace and authorization.
        self.executor.maintenance=Maintenance(self)

    def initial_state(self):return {'mode':'BASELINE','risk':self.m['services']['risk']['name'],'keycloak':self.m['services']['keycloak']['name'],'manifest':self.digest,'operation':None,'running_intent':dict.fromkeys(SERVICES,True)}
    def require_grant(self):need(self.grant.get() is True,'SHADOW_MUTATION_WITHOUT_NEW_OWNER_SIGNATURE')
    def authorize(self,envelope,operation,used=None,now=None):
        descriptor();legacy.owner_acl(ANCHOR)
        used={p.stem for p in (PRIVATE/'used').glob('*.json')} if used is None else used
        return verify(envelope,self.m,self.digest,r.sha_file(PACKET),operation,used,r.json_bytes(ANCHOR.read_bytes()),now)
    def initialize(self):
        self.require_grant()
        if PRIVATE.exists():self.module.private_acl();need((PRIVATE/'state.json').is_file(),'SHADOW_INCOMPLETE_INITIALIZATION');return
        PRIVATE.mkdir()
        sid=self.m['owner_sid'];proc=subprocess.run(['icacls',str(PRIVATE),'/inheritance:r','/grant:r','*'+sid+':(OI)(CI)F','*S-1-5-18:(OI)(CI)F'],capture_output=True)
        need(proc.returncode==0,'SHADOW_PRIVATE_ACL')
        for name in ('keys','journal','used','checkpoints','restore-env'):(PRIVATE/name).mkdir()
        self.module.atomic(PRIVATE/'state.key',os.urandom(32));self.module.sealed_write(PRIVATE/'state.json',self.initial_state());self.module.private_acl()
    def schema(self,name=None,allow_partial=False):return schema_state(self.executor.d.sql(name or self.m['services']['mysql']['name'],LEDGER).decode(),allow_partial)
    def candidate_spec(self,role):
        e=self.executor
        return contract.expected_spec(role,e.d.owned(self.m['services'][role]['name']),e.d.image(NEW[role]),self.m,PROJECT,CORE)
    def candidate_preflight(self):
        """Pure projection/inspection only: no create, journal, stop, DDL or writes."""
        need(self.schema()==7,'SHADOW_V3_REQUIRES_VALIDATED_V7_NO_DDL')
        for role in NEW:
            spec=self.candidate_spec(role)
            need(spec['contract']==self.m['release']['candidate_contracts'][role],'SHADOW_BOUND_CANDIDATE_CONTRACT_DRIFT')
        return {'status':'PASS','schema':7,'migration':'VALIDATED_V7_NO_OP','candidate_images':NEW,
                'canonical_environment':True,'active_mutation':False}
    def pre_cutover_unchanged(self,j):
        """Only terminally reject staging when the live selection/states are intact."""
        e=self.executor
        if j.get('active_mutation_started') or e.state()!=j['before']:return False
        for service in SERVICES:
            name=j['before'][service] if service in NEW else e.name(service)
            if e.d.owned(name)['State']['Running']!=j['running_before'][service]:return False
        for row in e.d.rows():
            labels=row['Config'].get('Labels') or {}
            if labels.get('io.zerotrust.operation')==j['id']:
                role=labels.get('io.zerotrust.role')
                if (role not in NEW or row['Id']!=j.get(role+'_id') or row['Name']!='/'+j.get(role+'_name','')
                    or labels.get('io.zerotrust.scope')!=PROJECT or labels.get('io.zerotrust.shadow.manifest')!=self.digest
                    or row['Image']!=NEW[role] or row['State']['Running'] or row['State']['Status']!='created'):return False
        return True
    def checkpoint_status(self,ident):
        # Read-only completion proof, not request-ID inference or restore acceptance.
        self.module.private_acl();e=self.executor;cp=e.load_checkpoint(ident)
        journal=self.module.sealed_read(e.journal(ident))
        need(cp['id']==ident and journal['id']==ident and journal['manifest']==self.digest and journal['operation']=='backup-only'
             and journal['status']=='DONE' and journal['stage']=='DONE' and journal.get('checkpoint')==ident,
             'SHADOW_BACKUP_NOT_COMPLETE')
        configs={v:'config-'+v.removeprefix(PROJECT+'_') for v in self.m['volumes'] if v.endswith('-config')}
        labels={'sql','redis','runtime-contract','execution-manifest',*configs.values()}
        need(cp['configs']==configs and set(cp['files'])==labels,'SHADOW_BACKUP_SCOPE_INCOMPLETE')
        key=PRIVATE/'keys'/(ident+'.key')
        need(key.is_file() and len(key.read_bytes())==32,'SHADOW_BACKUP_KEY_MISSING_OR_INVALID')
        for label in sorted(labels):
            data=e.unseal(cp,label)  # AES-GCM authentication in memory; never print/write plaintext.
            if label=='execution-manifest':need(canonical(r.json_bytes(data))==canonical(self.m),'SHADOW_BACKUP_MANIFEST_DRIFT')
        return {'status':'COMPLETE','checkpoint':ident,'encrypted_files_authenticated':len(labels),
                'independent_restore_verified':cp['restore_verified'],'age_seconds':round(time.time()-cp['created'],1),
                'APPLY_authorized':False,'D17':'PENDING','G8':'INTERNET_NO_GO'}
    def validate(self,healthy=False):
        descriptor();e=self.executor;state=e.state();rows=e.d.rows();running={};pending=e.unfinished()
        need(not self.old.engine.unfinished(),'SHADOW_OLD_OPERATION_PENDING')
        self.old.engine.verify_config() # Reuse frozen B0, TLS/CRL and dataset guards, independent of old selected-image state.
        for role in ('risk','keycloak'):
            for image in (OLD[role],NEW[role]):
                x=e.d.image(image);need(x['Id']==image and x['Os']=='linux' and x['Architecture']=='amd64','SHADOW_IMAGE_DRIFT')
                if image==NEW[role]:need(sha(canonical(x['Config'].get('Entrypoint')))==self.m['services'][role]['witness']['entrypoint_sha256'],'SHADOW_IMAGE_ENTRYPOINT_CHANGED')
        for service,rec in self.m['services'].items():e.d.owned(rec['name'])
        for role in ('risk','keycloak'):
            writers=[]
            for row in rows:
                if not row['State']['Running'] or CORE not in row['NetworkSettings']['Networks']:continue
                if row['Name'].startswith('/'+PROJECT+'-shadow-migrate-'):
                    self.verify_migrator(row);continue
                aliases=row['NetworkSettings']['Networks'][CORE].get('Aliases') or []
                if role in aliases or row['Image'] in (OLD[role],NEW[role]):
                    e.d.owned(row['Name'].lstrip('/'));writers.append(row['Id'])
            selected_name=state['risk'] if role=='risk' else state['keycloak']
            admit_writers(writers,e.d.owned(selected_name)['Id'],pending,role)
        for rec in self.m['runtime_files']:
            observed=e.d.inspect(rec['container']);need(observed['Id']==rec['container_id'] and (observed['Config'].get('Labels') or {}).get('io.zerotrust.scope')==PROJECT,'SHADOW_CONFIG_CONTAINER_DRIFT')
            need(sha(e.d.copied(rec['container'],rec['path']))==rec['sha256'],'SHADOW_TLS_CONFIG_DRIFT')
        for edition,rec in self.m['geoip']['files'].items():
            path=r.local_path(r.ROOT,self.m['geoip']['directory']+'/'+edition+'.mmdb');need(r.sha_file(path)==rec['sha256'],'SHADOW_GEOIP_DRIFT')
            built=dt.datetime.fromisoformat(rec['metadata']['build_at'].replace('Z','+00:00'));need(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=30)<=built,'SHADOW_GEOIP_STALE')
        nets={n['Name']:r.network_witness(n) for n in e.d.networks(list(self.m['networks']))};need(nets==self.m['networks'],'SHADOW_NETWORK_DRIFT')
        for volume in e.d.volumes(self.m['volumes']):need((volume.get('Labels') or {}).get('com.docker.compose.project')==PROJECT,'SHADOW_VOLUME_OWNERSHIP')
        for service in SERVICES:
            name=state['risk'] if service=='risk' else e.name(service);row=e.d.owned(name)
            expected=NEW.get(service) if state['mode']=='SHADOW' and service in NEW else self.m['services'][service]['witness']['image']
            need(row['Image']==expected,'SHADOW_SELECTED_IMAGE_MISMATCH')
            if healthy:e.d.health(name,service=='risk')
            running[service]={'name':name,'image':row['Image'],'running':row['State']['Running']}
        version=self.schema(allow_partial=bool(pending) or self.recovery_schema_allowed)
        need(e.d.sql(self.m['services']['mysql']['name'],'SELECT VERSION()').decode().strip()=='8.4.13','SHADOW_MYSQL_RUNTIME_VERSION')
        if healthy:need(version!=6,'SHADOW_PARTIAL_SCHEMA_REQUIRES_RECOVERY')
        need(state['mode']!='SHADOW' or version==7,'SHADOW_SELECTED_WITHOUT_SCHEMA7')
        return {'status':'PASS' if not pending else 'RECOVERY_REQUIRED','mode':state['mode'],'schema':version,'runtime':running,'unfinished':[j['id'] for j in pending],'authorization':'NEW_OWNER_SIGNATURE_REQUIRED','D17':'PENDING','G8':'INTERNET_NO_GO'}
    def verify_migrator(self,row):
        labels=row['Config'].get('Labels') or {};operation=labels.get('io.zerotrust.operation','')
        need(re.fullmatch('[0-9a-f]{32}',operation) and row['Name']=='/'+PROJECT+'-shadow-migrate-'+operation[:12]
             and labels.get('io.zerotrust.scope')==PROJECT and row['Image']==NEW['risk'],'SHADOW_FOREIGN_MIGRATOR')
        record=self.module.sealed_read(self.executor.journal(operation))
        need(record['manifest']==self.digest and record['operation']=='apply' and record['status']=='RUNNING','SHADOW_MIGRATOR_JOURNAL')
        mounts=row['Mounts']
        need(len(mounts)==1 and mounts[0].get('Name')==PROJECT+'_migrate-config' and not mounts[0]['RW']
             and row['Config']['Entrypoint']==['java'] and row['Config']['Cmd'][-1]=='Migrate'
             and set(row['NetworkSettings']['Networks'])=={CORE} and not row['HostConfig'].get('PortBindings'),'SHADOW_MIGRATOR_CONTRACT')
    def verify_replacement(self,row,operation=None):
        labels=row['Config'].get('Labels') or {};role=labels.get('io.zerotrust.role');h=row['HostConfig']
        need(role in NEW and row['Image']==NEW[role] and labels.get('io.zerotrust.shadow.manifest')==self.digest,'SHADOW_REPLACEMENT_PROVENANCE')
        need(re.fullmatch('[0-9a-f]{32}',labels.get('io.zerotrust.operation','')) and (operation is None or operation==labels['io.zerotrust.operation']),'SHADOW_REPLACEMENT_OPERATION')
        origin=self.executor.journal(labels['io.zerotrust.operation'])
        need(origin.is_file(),'SHADOW_REPLACEMENT_WITHOUT_JOURNAL')
        record=self.module.sealed_read(origin)
        need(record['operation']=='apply' and record['manifest']==self.digest and record.get(role+'_name')==row['Name'].lstrip('/')
             and (not record.get(role+'_id') or record[role+'_id']==row['Id']),'SHADOW_REPLACEMENT_ID_DRIFT')
        need(set(row['NetworkSettings']['Networks'])=={CORE} and not h.get('PortBindings') and not h['Privileged'],'SHADOW_REPLACEMENT_NETWORK')
        mounts={m['Destination']:m for m in row['Mounts']}
        required={'/run/demo','/geoip'} if role=='risk' else {'/run/secrets'}
        need(set(mounts)==required and all(not m['RW'] for m in mounts.values()),'SHADOW_REPLACEMENT_MOUNTS')
        config=mounts['/run/demo' if role=='risk' else '/run/secrets'];need(config.get('Name')==PROJECT+'_'+role+'-config','SHADOW_CONFIG_VOLUME')
        need(row['Config']['User']==('10001:10001' if role=='risk' else '65532:65532') and h['CapDrop']==['ALL']
             and any(s.startswith('no-new-privileges') for s in h.get('SecurityOpt') or []) and h['RestartPolicy']['Name']=='unless-stopped','SHADOW_HARDENING')
        env=dict(item.split('=',1) for item in row['Config']['Env'])
        baseline=self.m['services'][role]
        if role=='risk':
            expected=str(r.local_path(r.ROOT,self.m['geoip']['directory'])).replace('\\','/').lower().removeprefix('c:')
            need(mounts['/geoip']['Source'].replace('\\','/').lower().endswith(expected),'SHADOW_DATASET_MOUNT')
            need(json.loads(env.get('SPRING_APPLICATION_JSON','{}'))==self.m['release']['risk_override'] and h['ReadonlyRootfs'] and h['Memory']==640*1024**2,'SHADOW_CONFIG_OVERRIDE')
            need(contract.environment_hash(row['Config']['Env'])==self.m['release']['candidate_contracts']['risk']['environment_sha256']
                 and sha(canonical(row['Config']['Entrypoint']))==baseline['witness']['entrypoint_sha256']
                 and sha(canonical(row['Config']['Cmd']))==baseline['witness']['cmd_sha256'],'SHADOW_RISK_ENV_OR_ENTRYPOINT')
        else:
            need(contract.environment_hash(row['Config']['Env'])==self.m['release']['candidate_contracts']['keycloak']['environment_sha256'],'SHADOW_KC_ENV_DRIFT')
            need(sha(canonical(row['Config']['Cmd']))==self.m['release']['keycloak_cmd_sha256'],'SHADOW_KC_COMMAND')
            need(sha(canonical(row['Config']['Entrypoint']))==baseline['witness']['entrypoint_sha256']
                 and h['Memory']==baseline['witness']['memory'] and h['ReadonlyRootfs']==baseline['witness']['readonly_rootfs'],'SHADOW_KC_RUNTIME_CONTRACT')
        contract.verify_contract(row,self.m['release']['candidate_contracts'][role])
        aliases=set(row['NetworkSettings']['Networks'][CORE].get('Aliases') or [])
        need(role in aliases and aliases<={role,row['Name'].lstrip('/'),row['Id'][:12]},'SHADOW_UNEXPECTED_NETWORK_ALIAS')
    def quiesce(self,j,redis=False):
        self.require_grant();e=self.executor;targets=[];rows=e.d.rows()
        for role in NEW:
            writers=[row for row in rows if row['State']['Running'] and CORE in row['NetworkSettings']['Networks']
                     and (role in (row['NetworkSettings']['Networks'][CORE].get('Aliases') or []) or row['Image'] in (OLD[role],NEW[role]))]
            need(len(writers)<=1,'SHADOW_DUPLICATE_'+role.upper()+'_WRITER')
            for row in writers:e.d.owned(row['Name'].lstrip('/'))
        # Validate ALL running targets before the first stop. A dormant rejected
        # candidate is never a writer and needs no stop/ownership exception.
        for service in WRITERS:
            if service in NEW:
                for row in rows:
                    if not row['State']['Running']:continue
                    labels=row['Config'].get('Labels') or {}
                    if row['Name']== '/'+self.m['services'][service]['name'] or (labels.get('io.zerotrust.shadow.manifest')==self.digest and labels.get('io.zerotrust.role')==service):
                        name=row['Name'].lstrip('/');e.d.owned(name);targets.append(name)
            else:
                name=e.name(service)
                if e.d.owned(name)['State']['Running']:targets.append(name)
        if redis and e.d.owned(e.name('redis'))['State']['Running']:targets.append(e.name('redis'))
        e.stage(j,'QUIESCING',maintenance_verified=False,active_mutation_started=True)
        for name in targets:e.d.stop(name)
        e.stage(j,'QUIESCED')
    def verify_runtime(self):
        self.require_grant()
        e=self.executor;state=self.selection or e.state()
        need(not e.d.owned(self.m['services']['ingress']['name'])['State']['Running'],'SHADOW_INGRESS_NOT_CLOSED')
        for service in SERVICES:
            if service!='ingress':e.d.health(state['risk'] if service=='risk' else e.name(service),service=='risk')
        need(self.schema()==7 if state['mode']=='SHADOW' else self.schema(allow_partial=self.recovery_schema_allowed) in (5,6,7),'SHADOW_SCHEMA_RUNTIME')
        work=OUT/'checks'/uuid.uuid4().hex;work.mkdir(parents=True)
        e.helper('shadow-verify',['/tests/network_v2_postcheck.py'],[
            f'type=bind,source={r.ROOT/"target/full-function-20261111b/private"},target=/private,readonly',
            f'type=bind,source={HERE},target=/tests,readonly',f'type=bind,source={work},target=/results'],network=CORE,entrypoint='/opt/tools/bin/python',memory='192m')
        need(r.json_bytes((work/'result.json').read_bytes())['status']=='PASS','SHADOW_INTERNAL_TLS_OIDC_FAILED')
        return {'status':'PASS','owner_fresh_MFA_and_authenticated_smoke':'PENDING_MANUAL_POST_CUTOVER'}
    def resume(self,j,selected):
        self.require_grant()
        e=self.executor;self.selection=selected
        try:
            need(not e.d.owned(self.m['services']['ingress']['name'])['State']['Running'],'SHADOW_INGRESS_OPEN_EARLY')
            for service in SERVICES:
                if service!='ingress' and j['running_before'].get(service):
                    name=selected['risk'] if service=='risk' else e.name(service);e.d.start(name);e.d.health(name,service=='risk')
            self.verify_runtime();e.stage(j,'INTERNAL_VERIFIED',maintenance_verified=True)
            e.save_state(selected) # Durable selection only after internal verification; ingress is still closed.
            if j['running_before'].get('ingress'):
                e.d.start(e.name('ingress'));e.d.health(e.name('ingress'))
            for service in SERVICES:
                name=selected['risk'] if service=='risk' else e.name(service)
                need(e.d.owned(name)['State']['Running']==j['running_before'][service],'SHADOW_RUNNING_INTENT')
        except Exception:
            e.d.stop(e.name('ingress'));e.stage(j,'FAILED_CLOSED');raise
        finally:self.selection=None
    def create_role(self,j,role):
        self.require_grant();e=self.executor;spec=self.candidate_spec(role)
        need(spec['contract']==self.m['release']['candidate_contracts'][role],'SHADOW_BOUND_CANDIDATE_CONTRACT_DRIFT')
        name=PROJECT+'-shadow-'+role+'-'+j['id'][:12]
        e.stage(j,'WILL_CREATE_'+role.upper(),**{role+'_name':name})
        found=next((row for row in e.d.rows() if row['Name']=='/'+name),None)
        if found:
            self.verify_replacement(found,j['id'])
            need(not found['State']['Running'] and found['State']['Status']=='created','SHADOW_STAGING_CANDIDATE_NOT_DORMANT')
            return name
        envfile=PRIVATE/'restore-env'/(j['id']+'-'+role+'.env')
        self.module.atomic(envfile,('\n'.join(spec['env'])+'\n').encode())
        args=contract.create_args(spec,name,j['id'],self.digest,PROJECT,CORE,envfile,r.local_path(r.ROOT,self.m['geoip']['directory']))
        ident=e.d.raw(*args).decode().strip()
        e.stage(j,'CREATED_'+role.upper(),**{role+'_id':ident})
        row=e.d.inspect(name);self.verify_replacement(row,j['id'])
        need(not row['State']['Running'] and row['State']['Status']=='created','SHADOW_STAGING_CANDIDATE_NOT_DORMANT')
        return name
    def migrate(self,j):
        self.require_grant()
        need(self.schema()==7,'SHADOW_V3_REQUIRES_VALIDATED_V7_NO_DDL')
        self.executor.stage(j,'MIGRATION_NO_OP_VALIDATED_V7')
    def switch(self,j,selected):
        self.require_grant()
        e=self.executor;self.resume(j,selected);e.stage(j,'COMMITTED');e.finish(j);return e.state()
    def execute(self,envelope,operation):
        # Admission before private creation/project-lock writes; verify again under the shared lock.
        request=self.authorize(envelope,operation)
        self.recovery_schema_allowed=operation=='recover' and request['recover_target'] in ('BASELINE','STOPPED')
        if operation in ('apply','restore-verify'):self.executor.load_checkpoint(request['checkpoint'],operation=='apply')
        if operation=='apply':self.candidate_preflight()
        self.validate(operation in ('backup-only','apply'));token=self.grant.set(True)
        try:
            with self.old.module.ProjectLock():
                self.authorize(envelope,operation)
                if operation=='apply':self.candidate_preflight()
                self.initialize()
                if operation in ('backup-only','restore-verify'):
                    return getattr(self.executor,OPERATIONS[operation])(envelope)
                e=self.executor;j=e.new_operation(envelope,operation)
                try:
                    if operation=='apply':
                        need(j['before']['mode']=='BASELINE','SHADOW_ALREADY_SELECTED')
                        e.load_checkpoint(j['request']['checkpoint'],True);self.validate(True);self.candidate_preflight()
                        pair={role:self.create_role(j,role) for role in ('keycloak','risk')}
                        for role,name in pair.items():
                            row=e.d.inspect(name);self.verify_replacement(row,j['id'])
                            need(not row['State']['Running'] and row['State']['Status']=='created','SHADOW_STAGING_CANDIDATE_NOT_DORMANT')
                        e.stage(j,'CANDIDATES_VERIFIED_BEFORE_CUTOVER')
                        e.load_checkpoint(j['request']['checkpoint'],True);self.validate(True)
                        self.quiesce(j)
                        e.load_checkpoint(j['request']['checkpoint'],True);self.migrate(j)
                        selected={'mode':'SHADOW',**pair,'manifest':self.digest,'operation':j['id'],'checkpoint':j['request']['checkpoint'],'running_intent':j['running_before']}
                        return self.switch(j,selected)
                    if operation=='rollback':
                        need(j['before']['mode']=='SHADOW','SHADOW_ROLLBACK_REQUIRES_SHADOW');self.quiesce(j)
                        selected={**self.initial_state(),'operation':j['id'],'running_intent':j['running_before']}
                        return self.switch(j,selected)
                    if operation=='restart':
                        if not any(j['running_before'][service] for service in WRITERS):
                            j['running_before']=j['before']['running_intent'];e.stage(j,'RESTART_SAVED_RUNNING_INTENT')
                        self.quiesce(j);return self.switch(j,j['before'])
                    return self.recover(j)
                except Exception as error:
                    safe=False
                    if not j.get('active_mutation_started'):
                        try:safe=self.pre_cutover_unchanged(j)
                        except Exception:safe=False
                    failure=str(error) if isinstance(error,r.Rejected) else type(error).__name__
                    if safe:e.finish(j,result='REJECTED_BEFORE_CUTOVER',failure_code=failure,stopped_candidates={role:j.get(role+'_name') for role in NEW})
                    else:e.d.stop(self.m['services']['ingress']['name']);e.stage(j,'FAILED_CLOSED_RECOVERY_REQUIRED',failure_code=failure)
                    raise
        finally:self.grant.reset(token);self.recovery_schema_allowed=False
    def recover(self,j):
        self.require_grant()
        e=self.executor;target=self.module.sealed_read(e.journal(j['request']['recover_of']))
        need(target['manifest']==self.digest,'SHADOW_RECOVERY_MANIFEST')
        if target['status']=='DONE':e.finish(j,no_op=True);return e.state()
        e.stage(j,'RECOVERY_INTENT',active_mutation_started=True)
        desired=j['request']['recover_target']
        if target['operation']=='restore-verify':
            for row in e.d.rows():
                if (row['Config'].get('Labels') or {}).get('io.zerotrust.restore')==target['id']:e.d.stop(row['Name'].lstrip('/'))
        else:
            # A timed-out docker client does not prove the Flyway process exited.
            # Never start either service pair while an admitted migrator still runs.
            name=PROJECT+'-shadow-migrate-'+target['id'][:12]
            row=next((row for row in e.d.rows() if row['Name']=='/'+name),None)
            if row:
                self.verify_migrator(row)
                need(not row['State']['Running'],'SHADOW_MIGRATOR_STILL_RUNNING_WAIT_THEN_NEW_RECOVERY_REQUEST')
            self.quiesce(target,True)
            if desired=='STOPPED':selected=e.state()
            else:
                selected=target['before'] if desired==target['before']['mode'] else self.initial_state()
                if desired=='SHADOW':
                    need(e.state()['mode']=='SHADOW' and self.schema()==7,'SHADOW_RECOVERY_NOT_DURABLY_SELECTED');selected=e.state()
                # BASELINE always keeps current database/schema, including V7 or a partial V6.
                self.resume(target,selected)
        e.stage(target,'RECOVERED',status='DONE',recovered_by=j['id']);e.finish(j);return e.state()

class Maintenance:
    def __init__(self,context):self.c=context
    def enter(self,j,include_redis=False):self.c.quiesce(j,include_redis)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',nargs='?',default='plan',choices=('plan','status','candidate-check','checkpoint-status',*OPERATIONS));p.add_argument('--request',type=Path);p.add_argument('--checkpoint')
    args=p.parse_args();ctx=Context()
    if args.action in ('plan','status'):
        result=ctx.validate(healthy=args.action=='plan')
        if args.action=='plan':result['candidate_preflight']=ctx.candidate_preflight()
    elif args.action=='candidate-check':ctx.validate(False);result=ctx.candidate_preflight()
    elif args.action=='checkpoint-status':result=ctx.checkpoint_status(args.checkpoint)
    else:
        need(args.request is not None,'SHADOW_EXPLICIT_SIGNED_REQUEST_REQUIRED')
        result=ctx.execute(r.json_bytes(args.request.read_bytes()),args.action)
    print(json.dumps(result,indent=2))

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'status':'REJECTED','code':str(error) if isinstance(error,r.Rejected) else type(error).__name__}));raise SystemExit(1)
