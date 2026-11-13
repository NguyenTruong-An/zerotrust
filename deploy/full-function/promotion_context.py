"""Fixed active/disposable execution bindings over the reviewed promotion engine.

Each binding loads a separate module namespace: globals, locks, state keys and
ledgers never switch underneath another context. No arbitrary project/path CLI.
Active mutation requires an owner signature anchored OUTSIDE this repository.
This module contains no owner key generation, signing or approval function.
"""
import base64
from contextvars import ContextVar
import functools
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import promotion_executor as legacy
import risk_promotion as r

HERE=r.HERE
OUT=r.ROOT/(r.PREFIX+'phase23a-active-context')
DESCRIPTOR=HERE/'risk-active-execution.v1.json'
PACKET=HERE/'active-risk-cutover.PENDING.v2.json'
ACTIVE_PRIVATE=r.ROOT/(r.PREFIX+'promotion-private')
OWNER_ANCHOR=(Path.home()/'.zerotrust-owner/active-risk/anchor.json')
TASK_SHA='ee0f446ed6251d3414c2da92d6b1dbe8163a68ec7e9c270895143e7edf261c9c'
ACTIVE_KIND='REVIEWED_ACTIVE_EXECUTION_CONTEXT_SEPARATE_OWNER_AUTHORIZATION_REQUIRED'
BASE_PROPOSAL_SHA='0e73318230304040434ce0da03fa812ec61e486ccd9e76dd636e32ad05027b88'
CODE_FILES=('promotion_context.py','promotion_executor.py','promotion_maintenance.py',
            'active_risk_verify.py','risk_active_context.py','risk_promotion.py')
OPERATIONS={'backup-only':'backup','restore-verify':'restore_verify','apply':'apply','rollback':'rollback',
            'restart':'restart','stop':'stop','recover':'recover'}
DESCRIPTOR_FIELDS={'version','kind','project','authority_sha256','active_proposal_sha256','review_HEAD','services','volumes',
    'networks','config','policy','geoip','tls','proposed','receipts','D17','G8','approval_status','owner_sid','private_root',
    'owner_anchor','checkpoint_rules','authorization','implementation_sha256'}


def canonical(value):return legacy.canonical(value)


def current_sid():
    p=subprocess.run(['whoami','/user','/fo','csv','/nh'],capture_output=True,check=True)
    import csv,io
    return next(csv.reader(io.StringIO(p.stdout.decode().strip())))[1]


def owner_acl(path):
    r.need(os.name=='nt','OWNER_ANCHOR_REQUIRES_REVIEWED_WINDOWS_OWNER_ACL')
    quoted=str(path).replace("'","''")
    code=("$ErrorActionPreference='Stop';$p='"+quoted+"';$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value;"
          "$a=[System.IO.File]::GetAccessControl($p);$d=[System.IO.Directory]::GetAccessControl([System.IO.Path]::GetDirectoryName($p));"
          "foreach($acl in @($a,$d)){if(-not $acl.AreAccessRulesProtected){exit 23};foreach($e in $acl.Access){"
          "$s=$e.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value;"
          "if($s -notin @($sid,'S-1-5-18') -or $e.AccessControlType -ne 'Allow'){exit 24}}};[Console]::WriteLine('OWNER_SYSTEM_ONLY')")
    p=subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command',code],capture_output=True,timeout=20)
    r.need(p.returncode==0 and p.stdout.strip()==b'OWNER_SYSTEM_ONLY','OWNER_ANCHOR_ACL_INVALID')


def verify_owner_request(envelope,descriptor,descriptor_sha,packet_sha,operation,used,anchor,now=None):
    """Pure signature/binding verifier. Tests pass TEST fixtures, never real keys."""
    now=int(time.time()) if now is None else now
    r.need(type(envelope) is dict and set(envelope)=={'payload','signature'},'OWNER_ENVELOPE_SHAPE')
    p=envelope['payload']
    fields={'id','project','operation','descriptor_sha256','packet_sha256','old_image','new_image','config_sha256',
            'dataset_sha256','policy_sha256','maintenance','checkpoint','checkpoint_rules_sha256','rollback',
            'issued','expires','issuer','owner_sid','recover_of','recover_target'}
    r.need(type(p) is dict and set(p)==fields,'OWNER_REQUEST_SHAPE')
    r.need(p['project']==r.PROJECT and descriptor['project']==r.PROJECT,'OWNER_PROJECT_MISMATCH')
    r.need(type(p['id']) is str and re.fullmatch('[0-9a-f]{32}',p['id']) is not None,'OWNER_OPERATION_ID')
    r.need(p['id'] not in used,'OWNER_REQUEST_ALREADY_USED')
    r.need(type(p['issued']) is int and type(p['expires']) is int and p['issued']<=now+5 and now<p['expires']<=p['issued']+600,'OWNER_REQUEST_STALE')
    r.need(anchor.get('kind')=='OWNER_CONTROLLED_ACTIVE_ONLY' and anchor.get('project')==r.PROJECT
        and anchor.get('owner_sid')==descriptor['owner_sid'] and anchor.get('issuer')=='OWNER_EXPLICIT_ACTIVE_AUTHORIZATION','OWNER_ANCHOR_SCOPE')
    r.need(anchor.get('descriptor_sha256')==descriptor_sha and anchor.get('packet_sha256')==packet_sha,'OWNER_REVIEWED_DIGEST_MISMATCH')
    r.need(type(anchor.get('expires')) is int and now<anchor['expires'],'OWNER_ANCHOR_EXPIRED')
    r.need(operation in OPERATIONS and operation in anchor.get('operations',[]),'OWNER_OPERATION_NOT_AUTHORIZED')
    expected={'operation':operation,'descriptor_sha256':descriptor_sha,'packet_sha256':packet_sha,'old_image':r.OLD,'new_image':r.NEW,
        'config_sha256':r.sha(canonical(descriptor['proposed'])),'dataset_sha256':r.sha(canonical(descriptor['geoip'])),
        'policy_sha256':r.sha(canonical(descriptor['policy'])),'maintenance':list(legacy.WRITERS),
        'checkpoint_rules_sha256':r.sha(canonical(descriptor['checkpoint_rules'])),'rollback':r.OLD,
        'issuer':'OWNER_EXPLICIT_ACTIVE_AUTHORIZATION','owner_sid':descriptor['owner_sid']}
    r.need(all(p.get(k)==v for k,v in expected.items()),'OWNER_REQUEST_BINDING_MISMATCH')
    r.need(p['checkpoint'] is None or type(p['checkpoint']) is str and re.fullmatch('[0-9a-f]{32}',p['checkpoint']) is not None,'OWNER_CHECKPOINT_ID')
    if operation in ('apply','restore-verify'):r.need(p['checkpoint'] is not None,'OWNER_CHECKPOINT_REQUIRED')
    else:r.need(p['checkpoint'] is None,'OWNER_UNEXPECTED_CHECKPOINT')
    r.need(p['recover_of'] is None or type(p['recover_of']) is str and re.fullmatch('[0-9a-f]{32}',p['recover_of']) is not None,'OWNER_RECOVERY_REFERENCE')
    r.need(p['recover_target'] in (None,'BASELINE','PROMOTED','STOPPED'),'OWNER_RECOVERY_TARGET')
    r.need((operation=='recover')==(p['recover_of'] is not None),'OWNER_RECOVERY_OPERATION_SCOPE')
    if operation!='recover':r.need(p['recover_target'] is None,'OWNER_UNEXPECTED_RECOVERY_TARGET')
    try:
        key=base64.b64decode(anchor['public_key'],validate=True)
        r.need(r.sha(key)==anchor['public_key_sha256'],'OWNER_PUBLIC_KEY_FINGERPRINT')
        Ed25519PublicKey.from_public_bytes(key).verify(base64.b64decode(envelope['signature'],validate=True),canonical(p))
    except r.Rejected:raise
    except Exception:raise r.Rejected('OWNER_SIGNATURE_INVALID') from None
    return p


def load_owner_anchor():
    r.need(OWNER_ANCHOR.is_file(),'OWNER_TRUST_ANCHOR_NOT_ENROLLED')
    r.need(not OWNER_ANCHOR.is_symlink() and not OWNER_ANCHOR.parent.is_symlink(),'OWNER_ANCHOR_LINK_REJECTED')
    owner_acl(OWNER_ANCHOR)
    return r.json_bytes(OWNER_ANCHOR.read_bytes())


class Context:
    def __init__(self,name):
        r.need(name in ('active','disposable'),'UNKNOWN_EXECUTION_CONTEXT')
        self.name=name;self.active=name=='active';self.project=r.PROJECT if self.active else legacy.LANE
        self.descriptor=DESCRIPTOR if self.active else legacy.MANIFEST
        self.private=ACTIVE_PRIVATE if self.active else legacy.PRIVATE
        self._capability=ContextVar('promotion_capability_'+uuid.uuid4().hex,default=None)
        ident='_zt_promotion_engine_'+name+'_'+uuid.uuid4().hex
        spec=importlib.util.spec_from_file_location(ident,HERE/'promotion_executor.py')
        engine=importlib.util.module_from_spec(spec);sys.modules[ident]=engine;spec.loader.exec_module(engine)
        self.module=engine
        # Only compiled, fixed bindings are installed in this isolated namespace.
        engine.LANE=self.project;engine.CORE=self.project+'_core';engine.PRIVATE=self.private;engine.MANIFEST=self.descriptor
        if self.active:
            engine.OUT=OUT;engine.EXPECTED_KIND=ACTIVE_KIND;engine.AUTHORITY_SHA=TASK_SHA
            engine.scoped=lambda project:r.need(project==r.PROJECT,'ACTIVE_CONTEXT_PROJECT_MISMATCH')
            engine.authority=self.validate_descriptor
            engine.verify_request=lambda envelope,m,digest,op,used,now=None:self.authorize(envelope,op,used,now)
        self.m=r.json_bytes(self.descriptor.read_bytes());self.digest=r.sha_file(self.descriptor)
        self.validate_descriptor()
        context=self;original_docker=engine.Docker
        class BoundDocker(original_docker):
            def raw(self,*args,**kw):
                if not context.read_command(args):context.require_capability()
                elif len(args)>3 and args[1]=='exec':self.owned(args[2])
                return super().raw(*args,**kw)
            def owned(self,name):
                row=self.inspect(name);labels=row['Config'].get('Labels') or {}
                r.need(name.startswith(context.project+'-') and labels.get('io.zerotrust.scope')==context.project,'CONTEXT_FOREIGN_CONTAINER')
                expected={}
                for s,rec in context.m['services'].items():
                    if name==rec['name']:
                        r.need(row['Id']==rec['id'],'CONTEXT_CONTAINER_ID_DRIFT')
                        r.need(row['Image']==rec['witness']['image'],'CONTEXT_IMAGE_DRIFT');expected=rec['witness']['ports'] or {}
                r.need((row['HostConfig'].get('PortBindings') or {})==expected,'CONTEXT_UNEXPECTED_PUBLISHED_PORT')
                return row
        engine.Docker=BoundDocker
        original_executor=engine.Executor
        class BoundExecutor(original_executor):
            def save_state(self,value):context.require_capability();return super().save_state(value)
            def stage(self,*args,**kw):context.require_capability();return super().stage(*args,**kw)
            def state(self):
                if context.active and not (context.private/'state.json').exists():
                    r.need(not context.private.exists(),'ACTIVE_STATE_INITIALIZATION_INCOMPLETE')
                    return context.initial_state()
                return super().state()
            def smoke(self,mode):
                if not context.active:return super().smoke(mode)
                r.need(mode in ('internal-promoted','internal-baseline'),'ACTIVE_BROWSER_OR_FIXTURE_SCOPE_NOT_AUTHORIZED')
                work=OUT/'checks'/uuid.uuid4().hex;context.require_capability();work.mkdir(parents=True)
                self.helper('verify',['/tests/active_risk_verify.py',mode],[
                    f'type=bind,source={r.ROOT/(r.PREFIX+"private")},target=/private,readonly',
                    f'type=bind,source={HERE},target=/tests,readonly',f'type=bind,source={work},target=/results'],
                    network=context.project+'_core',entrypoint='/opt/tools/bin/python',memory='256m')
                result=r.json_bytes((work/'result.json').read_bytes());r.need(result['status']=='PASS','ACTIVE_INTERNAL_VERIFICATION_FAILED');return result
        for operation,method in OPERATIONS.items():
            base=getattr(original_executor,method)
            def guarded(self,envelope,_base=base,_operation=operation):
                # Admission precedes key/lock creation and every mutating Docker call.
                context.authorize(envelope,_operation)
                grant={'active':True,'project':context.project};token=context._capability.set(grant)
                try:
                    context.initialize_active_private()
                    return _base(self,envelope)
                finally:grant['active']=False;context._capability.reset(token)
            setattr(BoundExecutor,method,guarded)
        self.engine=BoundExecutor(path=self.descriptor)

    @staticmethod
    def read_command(args):
        if len(args)<2 or args[0]!='docker':return False
        if args[1] in ('ps','inspect','context','info'):return True
        if args[1] in ('image','volume','network') and len(args)>2 and args[2] in ('inspect','ls'):return True
        if args[1]=='cp':return len(args)==4 and args[-1]=='-' and ':' in args[2]
        if args[1]=='exec' and len(args)>4:
            # Read-only health/V5 calls; arbitrary exec and dump/import need a grant.
            if args[3]=='java':return args[3:] == ('java','@/run/demo/jvm.args','-cp','/app/tools','Health','https://risk:8443/actuator/health','200')
            if args[3]=='mysql' and '-e' in args:
                return args[3:]==('mysql','--defaults-extra-file=/fixture/root.cnf','--binary-as-hex','--batch','--raw','--skip-column-names',
                    '-e',"SELECT checksum,success FROM pd_staging_risk.flyway_schema_history WHERE version='5'")
        return False

    def require_capability(self):
        grant=self._capability.get()
        r.need(grant is not None and grant['active'] and grant['project']==self.project,'CONTEXT_MUTATION_WITHOUT_VERIFIED_AUTHORIZATION')
    def initial_state(self):
        return {'mode':'BASELINE','risk':self.m['services']['risk']['name'],'manifest':self.digest,'operation':None,
                'running_intent':dict.fromkeys(legacy.SERVICES,True)}
    def validate_descriptor(self):
        if not self.active:
            r.need(self.m['project']==legacy.LANE and self.descriptor==legacy.MANIFEST,'DISPOSABLE_CONTEXT_PROJECT_MISMATCH');return
        r.need(set(self.m)==DESCRIPTOR_FIELDS and self.m['version']==1,'ACTIVE_DESCRIPTOR_SHAPE')
        r.need(self.m['active_proposal_sha256']==BASE_PROPOSAL_SHA==r.sha_file(r.DEFAULT_MANIFEST),'ACTIVE_ORIGINAL_PROPOSAL_DRIFT')
        r.need(self.descriptor==DESCRIPTOR and self.m['project']==r.PROJECT and self.m['kind']==ACTIVE_KIND,'ACTIVE_DESCRIPTOR_IDENTITY')
        r.need(self.m['approval_status']=='PENDING' and self.m['authorization']=={'owner_signature_required':True,
            'issuer':'OWNER_EXPLICIT_ACTIVE_AUTHORIZATION','maximum_request_seconds':600},'ACTIVE_DESCRIPTOR_NOT_AN_AUTHORIZATION')
        r.need(self.m['private_root']==str(ACTIVE_PRIVATE.relative_to(r.ROOT)).replace('\\','/')
            and self.m['owner_anchor']==str(OWNER_ANCHOR).replace('\\','/'),'ACTIVE_COMPILED_BINDING_DRIFT')
        r.need(self.m['owner_sid']==current_sid(),'ACTIVE_OWNER_SID_MISMATCH')
        original=r.json_bytes(r.DEFAULT_MANIFEST.read_bytes())
        r.need(set(self.m['services'])==set(original['baseline_runtime']),'ACTIVE_SERVICE_SET_DRIFT')
        for service,witness in original['baseline_runtime'].items():
            expected=dict(witness)
            for k in ('entrypoint','cmd'):expected[k+'_sha256']=r.sha(canonical(expected.pop(k)))
            rec=self.m['services'][service]
            r.need(rec=={'name':r.PROJECT+'-'+service+'-1','id':witness['id'],'witness':expected},'ACTIVE_BASELINE_CONTRACT_DRIFT')
        r.need(self.m['checkpoint_rules']=={'maximum_age_seconds':1800,'independent_restore_required':True,'automatic_database_restore':False},'ACTIVE_CHECKPOINT_RULE_DRIFT')
        r.need(set(self.m['implementation_sha256'])==set(CODE_FILES),'ACTIVE_IMPLEMENTATION_SET')
        for path,sha in self.m['implementation_sha256'].items():r.need(r.sha_file(HERE/path)==sha,'ACTIVE_IMPLEMENTATION_DRIFT')
        p=r.json_bytes(PACKET.read_bytes())
        r.need(p['kind']=='PENDING_ACTIVE_CUTOVER_REVIEW_NOT_AUTHORIZATION' and p['approval_status']=='PENDING'
            and p['descriptor_sha256']==self.digest and p['project']==r.PROJECT,'ACTIVE_PACKET_DESCRIPTOR_DRIFT')
        r.need(p['old_packet_sha256']==r.sha_file(HERE/'active-risk-cutover.PENDING.json'),'HISTORICAL_PACKET_DRIFT')

    def authorize(self,envelope,operation,used=None,now=None):
        r.need(envelope is not None,'EXPLICIT_OPERATION_AUTHORIZATION_REQUIRED')
        self.validate_descriptor()
        used={p.stem for p in (self.private/'used').glob('*.json')} if used is None else used
        if self.active:
            return verify_owner_request(envelope,self.m,self.digest,r.sha_file(PACKET),operation,used,load_owner_anchor(),now)
        return legacy.verify_request(envelope,self.m,self.digest,operation,used,now)

    def initialize_active_private(self):
        if not self.active:return
        self.require_capability()
        if self.private.exists():
            r.need((self.private/'state.json').is_file(),'ACTIVE_STATE_INITIALIZATION_INCOMPLETE');self.module.private_acl();return
        self.private.mkdir()  # exclusive creation; no takeover of an existing root
        sid=current_sid()
        p=subprocess.run(['icacls',str(self.private),'/inheritance:r','/grant:r','*'+sid+':(OI)(CI)F','*S-1-5-18:(OI)(CI)F'],capture_output=True)
        r.need(p.returncode==0,'ACTIVE_PRIVATE_ACL_FAILED')
        for name in ('keys','journal','used','checkpoints','restore-env'):(self.private/name).mkdir()
        self.module.atomic(self.private/'state.key',os.urandom(32));self.module.sealed_write(self.private/'state.json',self.initial_state())
        self.module.private_acl()

    def preflight(self):
        self.validate_descriptor();r.need(not self.engine.unfinished(),'CONTEXT_PENDING_OPERATION_REQUIRES_RECOVERY')
        if self.active:r.need(self.engine.state()['mode']=='BASELINE','INITIAL_ACTIVE_PREFLIGHT_REQUIRES_BASELINE')
        result=self.engine.validate(require_healthy=self.active)
        if self.active or result['runtime']['mysql']['running']:self.engine.v5();result['V5']='661092940_VERIFIED_READ_ONLY'
        else:result['V5']='REUSE_PRIOR_DISPOSABLE_RECEIPT_STOPPED_MYSQL'
        result.update(context=self.name,descriptor_sha256=self.digest,packet_sha256=r.sha_file(PACKET) if self.active else None,
            authorization='SEPARATE_OWNER_SIGNATURE_REQUIRED' if self.active else 'TEST_HARNESS_ONLY',
            active_private_initialized=ACTIVE_PRIVATE.exists(),active_checkpoint='NOT_CREATED' if not ACTIVE_PRIVATE.exists() else 'INSPECT_PRIVATE_CHECKPOINT_JOURNAL',
            storage=self.module.storage_guard())
        return result
