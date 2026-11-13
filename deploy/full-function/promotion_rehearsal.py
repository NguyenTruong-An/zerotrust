"""Bounded harness for the owner's explicit disposable-only Phase2.3A request.

Signing keys below belong to TEST HARNESS, not the owner. No active-cutover owner
approval is generated. The executor has a compiled ceiling of one disposable lane.
"""
import argparse
import copy
import csv
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
import promotion_executor as x
import risk_promotion as r


def save(name,v):x.jwrite(x.OUT/name,v)


def init_private():
    r.local_path(r.ROOT,str(x.PRIVATE.relative_to(r.ROOT)).replace('\\','/'))
    x.PRIVATE.mkdir(parents=True,exist_ok=True)
    if os.name=='nt':
        raw=subprocess.run(['whoami','/user','/fo','csv','/nh'],capture_output=True,check=True).stdout.decode()
        sid=next(csv.reader(io.StringIO(raw.strip())))[1]
        p=subprocess.run(['icacls',str(x.PRIVATE),'/inheritance:r','/grant:r','*'+sid+':(OI)(CI)F','*S-1-5-18:(OI)(CI)F'],capture_output=True)
        r.need(p.returncode==0,'PRIVATE_ACL_FAILED')
    else:x.PRIVATE.chmod(0o700)
    for name in ('journal','used','requests','keys','checkpoints','fixtures','restore-env'):(x.PRIVATE/name).mkdir(exist_ok=True)


def prepare():
    x.authority();x.OUT.mkdir(exist_ok=True)
    if x.MANIFEST.exists():return x.Executor()
    d=x.Docker();rows=d.rows()
    owned={z['Config']['Labels']['com.docker.compose.service']:z for z in rows
        if (z['Config'].get('Labels') or {}).get('com.docker.compose.project')==x.LANE}
    r.need(set(owned)==set(x.SERVICES) and all(not z['State']['Running'] for z in owned.values()),'DISPOSABLE_LANE_NOT_STOPPED_OR_COMPLETE')
    for z in owned.values():
        r.need(z['Config']['Labels'].get('io.zerotrust.scope')==x.LANE and not z['HostConfig'].get('PortBindings'),'WRONG_OR_PUBLISHED_LANE')
        r.need(all(m['Type']=='volume' and m['Name'].startswith(x.LANE+'_') for m in z['Mounts']),'FOREIGN_LANE_VOLUME')
    init_private()
    key=x.Ed25519PrivateKey.generate()
    x.atomic(x.PRIVATE/'rehearsal-auth.key',key.private_bytes(x.Encoding.Raw,x.PrivateFormat.Raw,x.NoEncryption()))
    x.atomic(x.PRIVATE/'rehearsal-auth.pub',key.public_key().public_bytes(x.Encoding.Raw,x.PublicFormat.Raw))
    x.atomic(x.PRIVATE/'state.key',os.urandom(32))
    v1=r.json_bytes(r.DEFAULT_MANIFEST.read_bytes());r.schema_validate(v1,r.json_bytes((r.HERE/'risk-promotion.schema.json').read_bytes()))
    app=d.copied(owned['risk']['Name'].lstrip('/'),'/run/demo/application.properties')
    jvm=d.copied(owned['risk']['Name'].lstrip('/'),'/run/demo/jvm.args')
    defaults=v1['config']['artifact_defaults'];env=dict(z.split('=',1) for z in owned['risk']['Config']['Env'])
    policy=r.effective_policy(r.local_path(r.ROOT,defaults['path']).read_bytes(),app,env)
    r.need(policy==v1['policy'],'REHEARSAL_POLICY_NOT_EQUIVALENT')
    names=sorted({n for z in owned.values() for n in z['NetworkSettings']['Networks']})
    prefix=r.PREFIX+'phase2/restore/private/'
    def receipt(p):return {'path':p,'sha256':r.sha_file(r.local_path(r.ROOT,p))}
    m={'version':1,'project':x.LANE,'kind':'DISPOSABLE_REHEARSAL_NOT_OWNER_CUTOVER_APPROVAL','authority_sha256':x.AUTHORITY_SHA,
       'active_proposal_sha256':r.sha_file(r.DEFAULT_MANIFEST),'review_HEAD':r.ReadOnlyDocker().head(),
       'services':{s:{'name':z['Name'].lstrip('/'),'id':z['Id'],'witness':x.public_witness(z)} for s,z in owned.items()},
       'volumes':sorted({m['Name'] for z in owned.values() for m in z['Mounts']}),
       'networks':{z['Name']:r.network_witness(z) for z in d.networks(names)},
       'config':{'app_sha256':r.sha(app),'jvm_sha256':r.sha(jvm),'defaults':defaults},'policy':policy,'geoip':v1['geoip'],
       'tls':{k:receipt(prefix+p) for k,p in [('ca','risk/ca.crt'),('leaf','risk/server.crt'),('crl','ca.crl.pem')]},
       'proposed':{'image':r.NEW,'application':r.GEO,'security':v1['override']['security'],'rollback':r.OLD},
       'receipts':v1['receipts'],'D17':'PENDING','G8':'INTERNET_NO_GO'}
    x.jwrite(x.MANIFEST,m)
    x.sealed_write(x.PRIVATE/'state.json',{'mode':'BASELINE','risk':owned['risk']['Name'].lstrip('/'),'manifest':r.sha_file(x.MANIFEST),'operation':None})
    initial={z['Id']:{'witness':x.public_witness(z),'running':z['State']['Running']} for z in rows}
    save('preservation-before.json',{'containers':initial,'allowed_existing_ids':[z['Id'] for z in owned.values()],
        'protected_files':{v['path']:v['sha256'] for v in v1['receipts']},'authority':'Explicit current user request, disposable-only; no owner approval invented'})
    save('scope.json',{'project':x.LANE,'protected_project':r.PROJECT,'authority_document_sha256':x.AUTHORITY_SHA,
        'test_signer_public_sha256':r.sha_file(x.PRIVATE/'rehearsal-auth.pub'),'owner_approval_generated':False,'active_execution_enabled':False})
    return x.Executor()


def request(e,operation,checkpoint=None,recover_of=None,recover_target=None,expires=None):
    x.scoped(e.m['project']);x.authority();now=int(time.time())
    p={'id':uuid.uuid4().hex,'project':x.LANE,'manifest_sha256':e.digest,'operation':operation,'old_image':r.OLD,'new_image':r.NEW,
        'config_sha256':r.sha(x.canonical(e.m['proposed'])),'dataset_sha256':r.sha(x.canonical(e.m['geoip'])),
        'maintenance':list(x.WRITERS),'checkpoint':checkpoint,'rollback':r.OLD,'issued':now,'expires':now+600 if expires is None else expires,
        'authority':x.AUTHORITY_SHA,'issuer':'TEST_HARNESS_CURRENT_USER_REHEARSAL_ONLY','recover_of':recover_of,'recover_target':recover_target}
    key=x.Ed25519PrivateKey.from_private_bytes((x.PRIVATE/'rehearsal-auth.key').read_bytes())
    envelope={'payload':p,'signature':x.base64.b64encode(key.sign(x.canonical(p))).decode()}
    path=x.PRIVATE/'requests'/(p['id']+'.json');x.jwrite(path,envelope);return envelope,path


def child(stage,path):
    r.need(stage in ('QUIESCED','NEW_CREATED','COMMITTED'),'UNKNOWN_CRASH_BOUNDARY')
    def crash(s):
        if s==stage:os._exit(86)
    x.Executor(hook=crash).apply(r.json_bytes(Path(path).read_bytes()))


def run(resume=False):
    e=prepare();cases=r.json_bytes((x.OUT/'rehearsal.json').read_bytes())['cases'] if resume else []
    def record(case,**kw):
        cases.append({'case':case,'status':'PASS',**kw});save('rehearsal.json',{'cases':cases,'active_cutover':False,'D17':'PENDING','G8':'INTERNET_NO_GO'})
        print('PASS '+case,flush=True)
    def operation(name,**kw):
        ticket,_=request(e,name,**kw);start=time.monotonic()
        method={'restart':e.restart,'stop':e.stop,'backup-only':e.backup,'restore-verify':e.restore_verify,'apply':e.apply,'rollback':e.rollback,'recover':e.recover}[name]
        result=method(ticket);return result,ticket,round(time.monotonic()-start,2)
    def done(case):return any(c['case']==case for c in cases)
    try:
        if resume:
            for interrupted in list(e.unfinished()):
                operation('recover',recover_of=interrupted['id'],recover_target='PROMOTED' if e.state()['mode']=='PROMOTED' else 'BASELINE')
                record('Recovered interrupted tooling attempt without data restore',operation=interrupted['operation'])
            existing=next(c['checkpoint'] for c in reversed(cases) if c['case'] in
                ('Encrypted consistent checkpoint created and MAC/archive verified','Fresh checkpoint renewed for expiry gate, no stale-checkpoint bypass'))
            cp=e.load_checkpoint(existing)
            if any(not e.d.owned(e.current() if s=='risk' else e.name(s))['State']['Running'] for s in x.SERVICES):
                _,_,duration=operation('restart');record('Resumed stopped disposable services using durable selected state',seconds=duration)
            e.validate(require_healthy=True)
        else:
            save('initial-plan.json',e.validate());record('Read-only execution manifest/ownership validation')
            result,_,duration=operation('restart');record('Start retained disposable baseline without bootstrap/import',seconds=duration)
            e.smoke('prepare');record('Prepared only new synthetic trust/continuity subjects; existing credentials unchanged')
            cp,ticket,duration=operation('backup-only');record('Encrypted consistent checkpoint created and MAC/archive verified',checkpoint=cp['id'],seconds=duration)
            try:e.backup(ticket)
            except r.Rejected as ex:r.need(str(ex)=='REQUEST_ALREADY_USED','WRONG_REPLAY_REJECTION')
            else:raise r.Rejected('REUSED_REQUEST_ACCEPTED')
            record('One-use request replay rejected before quiescence')
        if not cp['restore_verified']:
            restored,_,duration=operation('restore-verify',checkpoint=cp['id']);record('Independent MySQL/Redis restore and complete schema-data witnesses',**restored,seconds=duration)
        def fresh_checkpoint():
            nonlocal cp
            if time.time()-cp['created']>1500:
                cp,_,duration=operation('backup-only');operation('restore-verify',checkpoint=cp['id'])
                cp=e.load_checkpoint(cp['id']);record('Fresh checkpoint renewed for expiry gate, no stale-checkpoint bypass',checkpoint=cp['id'],seconds=duration)
        fresh_checkpoint()
        # Record rejection without changing any protected/active resource.
        if not done('Stale apply request rejected'):
            stale,_=request(e,'apply',checkpoint=cp['id'],expires=int(time.time())-1)
            try:e.apply(stale)
            except r.Rejected as ex:r.need(str(ex)=='REQUEST_STALE','WRONG_STALE_REJECTION')
            else:raise r.Rejected('STALE_REQUEST_ACCEPTED')
            record('Stale apply request rejected')
        if not done('Exact Risk-only apply, hardening and real GeoIP/browser/OTP/Recovery/B0 smoke'):
            result,_,duration=operation('apply',checkpoint=cp['id']);record('Exact Risk-only apply, hardening and real GeoIP/browser/OTP/Recovery/B0 smoke',seconds=duration,risk=result['risk'])
        if not done('Changed synthetic generation/pending/revoked trust AFTER checkpoint to prove rollback keeps current state'):
            e.smoke('mutate');record('Changed synthetic generation/pending/revoked trust AFTER checkpoint to prove rollback keeps current state')
        if not done('Cold stop/start selects durable promoted Risk; no old-image revert'):
            result,_,duration=operation('stop');result,_,duration2=operation('restart')
            record('Cold stop/start selects durable promoted Risk; no old-image revert',seconds=duration+duration2,risk=result['risk'])
        if not done('Exact old image rollback preserves current generation/pending/audit/credentials'):
            result,_,duration=operation('rollback');record('Exact old image rollback preserves current generation/pending/audit/credentials',seconds=duration)
        for boundary in ('QUIESCED','NEW_CREATED','COMMITTED'):
            if done('Actual process crash/recovery at '+boundary):continue
            if e.state()['mode']=='PROMOTED':operation('rollback')
            fresh_checkpoint()
            ticket,path=request(e,'apply',checkpoint=cp['id'])
            p=subprocess.run([sys.executable,'-B',str(r.HERE/'promotion_rehearsal.py'),'crash-child','--boundary',boundary,'--request',str(path)],
                cwd=r.ROOT,capture_output=True,timeout=600)
            r.need(p.returncode==86,'CRASH_INJECTION_DID_NOT_REACH_BOUNDARY')
            old=ticket['payload']['id'];journal=x.sealed_read(e.journal(old));r.need(journal['stage']==boundary and journal['status']=='RUNNING','CRASH_JOURNAL_NOT_DURABLE')
            target='PROMOTED' if boundary=='COMMITTED' else 'BASELINE'
            result,_,duration=operation('recover',recover_of=old,recover_target=target)
            record('Actual process crash/recovery at '+boundary,seconds=duration,mode=result['mode'],interrupted_operation=old)
            result,_,_=operation('recover',recover_of=old,recover_target=target);record('Idempotent new recovery request at '+boundary)
            if result['mode']=='PROMOTED':operation('rollback')
        save('final-status.json',e.validate(require_healthy=True));record('Final disposable baseline healthy and state continuity verified')
    finally:
        # No destructive cleanup. If an operation is incomplete, retain explicit
        # recovery metadata rather than guessing a fallback configuration.
        if not e.unfinished():
            try:operation('stop')
            except Exception:save('stop-needed.json',{'status':'MANUAL_RECOVERY_NEEDED','project':x.LANE})
        else:save('recovery-needed.json',{'status':'EXPLICIT_RECOVERY_REQUIRED','operations':[j['id'] for j in e.unfinished()]})
        preserve(e)


def preserve(e):
    before=r.json_bytes((x.OUT/'preservation-before.json').read_bytes());now={z['Id']:z for z in e.d.rows()}
    for ident,old in before['containers'].items():
        r.need(ident in now and x.public_witness(now[ident])==old['witness'],'EXISTING_CONTAINER_CONTRACT_CHANGED')
        if ident not in before['allowed_existing_ids']:r.need(now[ident]['State']['Running']==old['running'],'PROTECTED_RUNNING_STATE_CHANGED')
    for p,digest in before['protected_files'].items():r.need(r.sha_file(r.local_path(r.ROOT,p))==digest,'PROTECTED_RECEIPT_CHANGED')
    active=[z for z in now.values() if z['Name'].startswith('/'+r.PROJECT+'-') and z['State']['Running']]
    r.need(len(active)==9 and all(z['State'].get('Health',{}).get('Status')=='healthy' for z in active),'ACTIVE_STACK_HEALTH_CHANGED')
    save('preservation.json',{'status':'PASS','existing_containers':len(before['containers']),'active_healthy':9,
        'active_risk':next(z['Image'] for z in active if z['Name'].endswith('-risk-1')),'active_geoip':False,
        'protected_receipts_unchanged':len(before['protected_files']),'owner_approval_generated':False,'D17':'PENDING','G8':'INTERNET_NO_GO'})


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('prepare','run','resume','crash-child'))
    parser.add_argument('--boundary');parser.add_argument('--request');args=parser.parse_args()
    try:
        if args.action=='prepare':prepare();print('PASS initialized private disposable harness, not owner approval')
        elif args.action in ('run','resume'):run(args.action=='resume')
        else:child(args.boundary,args.request)
    except Exception as ex:
        import traceback
        failure={'status':'FAIL','type':type(ex).__name__,'line':traceback.extract_tb(ex.__traceback__)[-1].lineno}
        if type(ex) is r.Rejected:failure['code']=str(ex)
        x.OUT.mkdir(exist_ok=True);save('failure.json',failure);print('BLOCKED '+json.dumps(failure),flush=True);raise SystemExit(1)
