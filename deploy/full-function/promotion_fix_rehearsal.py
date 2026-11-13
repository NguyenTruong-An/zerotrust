"""Bounded Phase2.3A-FIX runtime checks; disposable scope only, no broad suites.

Retain prior receipts. One fresh verified checkpoint is necessary for APPLY;
reuse the reviewed Risk container/image and original disposable databases.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import traceback
import promotion_executor as x
import promotion_rehearsal as h
import risk_promotion as r

OUT=x.OUT.with_name('phase23a-fix')


def save(name,value):x.jwrite(OUT/name,value)


def snapshot(e):
    rows=e.d.rows();files={}
    for rec in e.m['receipts']:files[rec['path']]=rec['sha256']
    old=r.json_bytes((r.ROOT/'target/full-function-20261111/protected-before.json').read_bytes())['files']
    files.update(old)
    for p in x.OUT.rglob('*.json'):
        if 'private' not in p.relative_to(x.OUT).parts:files[str(p.relative_to(r.ROOT))]=r.sha_file(p)
    files['deploy/full-function/risk-promotion.v1.json']=r.sha_file(r.DEFAULT_MANIFEST)
    files['target/full-function-20261111b/phase23a/execution-manifest.json']=e.digest
    save('preservation-before.json',{'containers':{z['Id']:{'witness':x.public_witness(z),'running':z['State']['Running']} for z in rows},
        'files':files,'images':sorted(set(e.d.raw('docker','image','ls','--no-trunc','--format','{{.ID}}').decode().split())),
        'volumes':sorted(e.d.raw('docker','volume','ls','--format','{{.Name}}').decode().split()),
        'free_bytes':shutil.disk_usage(r.ROOT.anchor).free,'authority':'Current user Phase2.3A-FIX; disposable only; no active cutover'})


def preservation(e):
    before=r.json_bytes((OUT/'preservation-before.json').read_bytes());rows={z['Id']:z for z in e.d.rows()}
    for ident,old in before['containers'].items():
        r.need(ident in rows and x.public_witness(rows[ident])==old['witness'],'EXISTING_RUNTIME_CONTRACT_CHANGED')
        r.need(rows[ident]['State']['Running']==old['running'],'INITIAL_RUNNING_STATE_NOT_RESTORED')
    for p,sha in before['files'].items():r.need(r.sha_file(r.ROOT/p)==sha,'EXISTING_RECEIPT_OR_PROTECTED_FILE_CHANGED')
    active=[z for z in rows.values() if (z['Config'].get('Labels') or {}).get('com.docker.compose.project')==r.PROJECT and z['State']['Running']]
    r.need(len(active)==9 and all(z['State'].get('Health',{}).get('Status')=='healthy' for z in active),'ACTIVE_HEALTH_DRIFT')
    images=sorted(set(e.d.raw('docker','image','ls','--no-trunc','--format','{{.ID}}').decode().split()))
    r.need(images==before['images'],'UNEXPECTED_NEW_IMAGE')
    free=shutil.disk_usage(r.ROOT.anchor).free
    save('preservation.json',{'status':'PASS','existing_containers_unchanged':len(before['containers']),'protected_files_unchanged':len(before['files']),
        'active_healthy':9,'active_image':r.OLD,'active_geoip':False,'unfinished_operations':len(e.unfinished()),
        'free_before_bytes':before['free_bytes'],'free_after_bytes':free,'free_delta_bytes':before['free_bytes']-free,
        'new_images':0,'new_volumes':sorted(set(e.d.raw('docker','volume','ls','--format','{{.Name}}').decode().split())-set(before['volumes'])),
        'new_containers':[{'name':z['Name'],'running':z['State']['Running']} for ident,z in rows.items() if ident not in before['containers']],
        'warning_below_20_GiB':free<20*1024**3,'D17':'PENDING','G8':'INTERNET_NO_GO'})


def continuity_witness(e):
    f=r.json_bytes((x.PRIVATE/'fixtures/continuity.json').read_bytes());subject=f['low_subject']
    r.need(re.fullmatch('[0-9a-f-]{36}',subject) is not None,'SYNTHETIC_SUBJECT_FORMAT')
    result={'school':e.data_witness()['pd_staging_school']}
    for table,order in [('keycloak.CREDENTIAL','ID'),('risk.subject_device_trust','subject_id'),
                        ('risk.known_devices','id'),('risk.device_trust_revocations','operation_id')]:
        where='' if table.startswith('keycloak.') else " WHERE subject_id='"+subject+"'"
        result[table]=r.sha(e.d.sql(e.name('mysql'),'SELECT * FROM pd_staging_'+table+where+' ORDER BY '+order))
    return result


def crash_rollback(request_path):
    e=x.Executor()
    def crash(stage):
        if stage=='ROLLBACK_OLD_STARTED':
            r.need(not e.d.owned(e.name('ingress'))['State']['Running'],'INGRESS_OPEN_DURING_ROLLBACK')
            e.d.health(e.name('risk'));save('rollback-frozen-'+r.json_bytes(Path(request_path).read_bytes())['payload']['id']+'.json',continuity_witness(e))
            os._exit(86)
    e.hook=crash;e.rollback(r.json_bytes(Path(request_path).read_bytes()))


def run():
    OUT.mkdir(exist_ok=True);e=x.Executor();cases=r.json_bytes((OUT/'runtime.json').read_bytes())['cases'] if (OUT/'runtime.json').exists() else []
    def done(name):return next((v for v in cases if v['case']==name),None)
    def record(name,**kw):
        cases.append({'case':name,'status':'PASS',**kw});save('runtime.json',{'cases':cases,'active_cutover':False,'D17':'PENDING','G8':'INTERNET_NO_GO'})
        print('PASS '+name,flush=True)
    def op(name,**kw):
        ticket,_=h.request(e,name,**kw);start=time.monotonic()
        value={'restart':e.restart,'stop':e.stop,'backup-only':e.backup,'restore-verify':e.restore_verify,'apply':e.apply,'recover':e.recover}[name](ticket)
        return value,round(time.monotonic()-start,2)
    if not (OUT/'preservation-before.json').exists():snapshot(e)
    try:
        r.need(not e.unfinished(),'EXPLICIT_RECOVERY_REQUIRED_BEFORE_RESUME')
        if not done('Changed maintenance baseline restart'):
            value,seconds=op('restart');record('Changed maintenance baseline restart',seconds=seconds)
        if not any(e.d.owned(e.current() if s=='risk' else e.name(s))['State']['Running'] for s in x.SERVICES):
            op('restart');record('Resume known baseline after explicit stopped recovery')
        if not done('Preserve deliberately stopped ingress and frontend'):
            for s in ('ingress','frontend'):e.d.stop(e.name(s))
            _,seconds=op('restart')
            r.need(all(not e.d.owned(e.name(s))['State']['Running'] for s in ('ingress','frontend')),'STOPPED_SERVICE_INTENT_LOST')
            record('Preserve deliberately stopped ingress and frontend',seconds=seconds)
        if not done('One fresh disposable checkpoint available'):
            recovered=OUT/'recovered-checkpoint.json'
            if recovered.exists():
                cp=e.load_checkpoint(r.json_bytes(recovered.read_bytes())['checkpoint']);seconds=0
            else:cp,seconds=op('backup-only')
            record('One fresh disposable checkpoint available',checkpoint=cp['id'],seconds=seconds,reused_after_safe_recovery=recovered.exists())
        cp=e.load_checkpoint(done('One fresh disposable checkpoint available')['checkpoint'])
        if not done('Fresh checkpoint independent restore verification'):
            value,seconds=op('restore-verify',checkpoint=cp['id']);record('Fresh checkpoint independent restore verification',seconds=seconds,**value)
        if not done('Candidate reuse with ingress closed until committed verification'):
            for s in ('frontend','ingress'):e.d.start(e.name(s));e.d.health(e.name(s))
            value,seconds=op('apply',checkpoint=cp['id']);j=x.sealed_read(e.journal(value['operation']))
            r.need(j.get('reused_candidate') and j.get('maintenance_verified'),'REUSED_CANDIDATE_OR_VERIFICATION_MISSING')
            record('Candidate reuse with ingress closed until committed verification',seconds=seconds,risk=value['risk'],reused=True)
        for desired in ('PROMOTED','BASELINE'):
            name='Rollback crash at OLD_STARTED and recover '+desired
            if done(name):continue
            ticket,path=h.request(e,'rollback');start=time.monotonic()
            p=subprocess.run([sys.executable,'-B',str(Path(__file__)),'crash-rollback','--request',str(path)],cwd=r.ROOT,capture_output=True,timeout=420)
            r.need(p.returncode==86,'ROLLBACK_CRASH_NOT_REACHED');ident=ticket['payload']['id'];j=x.sealed_read(e.journal(ident))
            r.need(j['stage']=='ROLLBACK_OLD_STARTED' and j['status']=='RUNNING','ROLLBACK_JOURNAL_NOT_DURABLE')
            status=e.validate();r.need(status['status']=='OPERATION_RUNNING_OR_RECOVERY_REQUIRED','PARTIAL_STATE_NOT_VISIBLE')
            blocked,_=h.request(e,'restart')
            try:e.restart(blocked)
            except r.Rejected as ex:r.need(str(ex)=='INTERRUPTED_OPERATION_REQUIRES_RECOVER','WRONG_INTERRUPTED_REJECTION')
            else:raise r.Rejected('PARTIAL_RESTART_NOT_REJECTED')
            value,_=op('recover',recover_of=ident,recover_target=desired)
            r.need(value['mode']==desired and continuity_witness(e)==r.json_bytes((OUT/('rollback-frozen-'+ident+'.json')).read_bytes()),'RECOVERY_LOST_CURRENT_SECURITY_STATE')
            e.validate(require_healthy=True)
            value,_=op('recover',recover_of=ident,recover_target=desired)
            r.need(value['mode']==desired,'RECOVERY_NOT_IDEMPOTENT')
            record(name,operation=ident,seconds=round(time.monotonic()-start,2),journal_survived=True,continuity=True,
                restart_rejected=True,idempotent_new_recovery_request=True,exact_image=r.NEW if desired=='PROMOTED' else r.OLD)
            if desired=='PROMOTED' and not done('Changed promoted cold stop/start selects exact NEW'):
                op('stop');value,seconds=op('restart')
                r.need(value['mode']=='PROMOTED' and e.d.owned(value['risk'])['Image']==r.NEW,'PROMOTED_RESTART_REVERTED')
                record('Changed promoted cold stop/start selects exact NEW',seconds=seconds)
        save('healthy-final-status.json',e.validate(require_healthy=True))
    except Exception as exc:
        attempt={'status':'FAIL','type':type(exc).__name__,'line':traceback.extract_tb(exc.__traceback__)[-1].lineno}
        if type(exc) is r.Rejected:attempt['code']=str(exc)
        save('attempt-'+str(int(time.time()))+'.json',attempt);raise
    finally:
        if not e.unfinished():op('stop')
        save('stopped-status.json',e.validate())
        if not e.unfinished():preservation(e)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('run','crash-rollback'));p.add_argument('--request');args=p.parse_args()
    try:
        if args.action=='run':run()
        else:crash_rollback(args.request)
    except Exception as exc:
        failure={'status':'FAIL','type':type(exc).__name__,'line':traceback.extract_tb(exc.__traceback__)[-1].lineno}
        if type(exc) is r.Rejected:failure['code']=str(exc)
        save('failure.json',failure);print(json.dumps(failure),flush=True);raise SystemExit(1)
