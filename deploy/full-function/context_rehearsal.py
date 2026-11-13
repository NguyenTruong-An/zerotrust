"""New context namespace/authorization regression on retained disposable state.

No build, new backup/volume, realm/account reset, promotion or active mutation.
Rollback runtime/backup/GeoIP/browser receipts from previous phases are reused.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback
import promotion_context as c
import promotion_executor as x
import promotion_rehearsal as h
import promotion_fix_rehearsal as f
import risk_promotion as r


def save(name,v):x.jwrite(c.OUT/name,v)


def preserve():
    before=r.json_bytes((c.OUT/'preservation-before.json').read_bytes());d=x.Docker();rows={z['Id']:z for z in d.rows()}
    for ident,old in before['containers'].items():
        r.need(ident in rows and x.public_witness(rows[ident])==old['witness'],'CONTAINER_CONTRACT_CHANGED')
        r.need(rows[ident]['State']['Running']==old['running'],'INITIAL_RUNNING_STATE_NOT_RESTORED')
    for p,sha in before['files'].items():r.need(r.sha_file(r.ROOT/p)==sha,'HISTORICAL_RECEIPT_CHANGED')
    r.need(sorted(d.raw('docker','volume','ls','--format','{{.Name}}').decode().split())==before['volumes'],'NEW_VOLUME_CREATED')
    r.need(sorted(set(d.raw('docker','image','ls','--no-trunc','--format','{{.ID}}').decode().split()))==before['images'],'NEW_IMAGE_CREATED')
    r.need(set(rows)==set(before['containers']),'UNEXPECTED_RETAINED_CONTAINER')
    active=[z for z in rows.values() if (z['Config'].get('Labels') or {}).get('com.docker.compose.project')==r.PROJECT and z['State']['Running']]
    r.need(len(active)==9 and all(z['State'].get('Health',{}).get('Status')=='healthy' for z in active),'ACTIVE_HEALTH_CHANGED')
    r.need(not c.ACTIVE_PRIVATE.exists(),'ACTIVE_PRIVATE_STATE_CREATED')
    free=x.shutil.disk_usage(r.ROOT.anchor).free
    save('preservation.json',{'status':'PASS','existing_containers':len(rows),'protected_hashes':len(before['files']),
        'active_healthy':9,'active_risk':r.OLD,'active_geoip':False,'active_private_initialized':False,
        'active_checkpoint':'NOT_CREATED','owner_anchor_created':False,'new_images':0,'new_volumes':0,'new_retained_containers':0,
        'free_before_bytes':before['free_bytes'],'free_after_bytes':free,'net_free_delta_bytes':before['free_bytes']-free,
        'D17':'PENDING','G8':'INTERNET_NO_GO'})


def active_helper_on_disposable(ctx,mode):
    work=c.OUT/'disposable-active-verifier';work.mkdir(exist_ok=True)
    ctx.engine.helper('context-verifier',['/tests/active_risk_verify.py',mode],[
        f'type=bind,source={r.ROOT/(r.PREFIX+"phase2/restore/private")},target=/private,readonly',
        f'type=bind,source={r.HERE},target=/tests,readonly',f'type=bind,source={work},target=/results'],
        network=x.CORE,entrypoint='/opt/tools/bin/python',memory='256m')
    result=r.json_bytes((work/'result.json').read_bytes());r.need(result['status']=='PASS','ACTIVE_HELPER_DISPOSABLE_TEST_FAILED')


def run():
    ctx=c.Context('disposable');e=ctx.engine;cases=[]
    def record(name,**kw):
        cases.append({'case':name,'status':'PASS',**kw});save('runtime.json',{'cases':cases,'project':x.LANE,'active_mutations':0})
        print('PASS '+name,flush=True)
    def op(name,**kw):
        ticket,_=h.request(e,name,**kw);start=time.monotonic()
        result=getattr(e,c.OPERATIONS[name])(ticket);return result,ticket,round(time.monotonic()-start,2)
    try:
        r.need(e.state()['mode']=='BASELINE' and not e.unfinished(),'UNEXPECTED_DISPOSABLE_STATE')
        ran=[False]
        def check(stage):
            if stage=='MAINTENANCE_VERIFIED' and not ran[0]:
                r.need(not e.d.owned(e.name('ingress'))['State']['Running'],'INGRESS_OPEN_DURING_INTERNAL_CHECK')
                active_helper_on_disposable(ctx,'internal-baseline');ran[0]=True
        e.hook=check;_,_,seconds=op('restart');e.hook=lambda s:None
        record('New context restart and active helper against disposable TLS/JWT/B0 with ingress closed',seconds=seconds)
        witness=f.continuity_witness(x.Executor());save('current-security-witness.json',witness)
        ticket,path=h.request(e,'restart')
        p=subprocess.run([sys.executable,'-B',str(Path(__file__)),'crash-restart','--request',str(path)],capture_output=True,cwd=r.ROOT,timeout=180)
        r.need(p.returncode==86,'CONTEXT_CRASH_NOT_REACHED')
        j=ctx.module.sealed_read(e.journal(ticket['payload']['id']))
        r.need(j['stage']=='STOPPED_FOR_RESTART' and j['status']=='RUNNING','CONTEXT_JOURNAL_NOT_DURABLE')
        blocked,_=h.request(e,'restart')
        try:e.restart(blocked)
        except r.Rejected as exc:r.need(str(exc)=='INTERRUPTED_OPERATION_REQUIRES_RECOVER','WRONG_INTERRUPTED_REJECTION')
        else:raise r.Rejected('UNFINISHED_OPERATION_NOT_REJECTED')
        ident=ticket['payload']['id'];_,recovery,seconds=op('recover',recover_of=ident,recover_target='BASELINE')
        r.need(f.continuity_witness(x.Executor())==witness,'CONTEXT_RECOVERY_LOST_CURRENT_SECURITY_STATE')
        op('recover',recover_of=ident,recover_target='BASELINE')
        try:e.recover(recovery)
        except r.Rejected as exc:r.need(str(exc)=='REQUEST_ALREADY_USED','WRONG_REPLAY_REJECTION')
        else:raise r.Rejected('CONTEXT_REPLAY_ACCEPTED')
        record('Actual new-context restart interruption/recovery, idempotence, replay rejection and CURRENT security-state preservation',seconds=seconds)
        e.validate(require_healthy=True);record('Exact disposable identities, B0/V5/TLS health and no conflicting Risk writer')
    finally:
        if not e.unfinished():op('stop')
        save('disposable-status.json',e.validate())
        if not e.unfinished():preserve()


def child(path):
    ctx=c.Context('disposable')
    def crash(stage):
        if stage=='STOPPED_FOR_RESTART':os._exit(86)
    ctx.engine.hook=crash;ctx.engine.restart(r.json_bytes(Path(path).read_bytes()))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('run','crash-restart'));p.add_argument('--request');a=p.parse_args()
    try:
        if a.action=='run':run()
        else:child(a.request)
    except Exception as exc:
        failure={'status':'FAIL','type':type(exc).__name__,'line':traceback.extract_tb(exc.__traceback__)[-1].lineno}
        if type(exc) is r.Rejected:failure['code']=str(exc)
        save('failure.json',failure);print(json.dumps(failure));raise SystemExit(1)
