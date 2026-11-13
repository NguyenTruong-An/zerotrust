"""Real MySQL/HTTP race regression against only the isolated locking candidate."""
from concurrent.futures import ThreadPoolExecutor
import json
import traceback
import uuid
import verify as v
from phase2_security import browser_setup


def main():
    caller=v.service_token('zerotrust-risk-caller');admin=v.service_token('zerotrust-portal-risk-admin')
    cases=[]
    def record(case,**details):
        cases.append({'case':case,'status':'PASS',**details})
        (v.RESULTS/'locking-http.json').write_text(json.dumps({'cases':cases,'release_promotion':False,'D17':'PENDING','G8':'INTERNET_NO_GO'},indent=2)+'\n')
        print('PASS '+case,flush=True)
    def revoke(subject,op):return v.request('https://risk:8443/internal/v1/subjects/'+subject+'/trusted-devices/revocations','POST',op,admin)[0]
    for seeded in (False,True):
        subject=str(uuid.uuid4())
        if seeded:v.evaluate(subject,None,caller)
        op={'operationId':str(uuid.uuid4()),'requestedBy':'phase2-locking-candidate'}
        with ThreadPoolExecutor(max_workers=2) as pool:statuses=list(pool.map(lambda _:revoke(subject,op),range(2)))
        v.require(statuses==[204,204],'Concurrent identical operation failed: '+str(statuses))
        v.require(v.sql('SELECT generation FROM pd_staging_risk.subject_device_trust WHERE subject_id=%s',(subject,))[0][0]==1,'Same operation incremented generation twice')
        operations=[{'operationId':str(uuid.uuid4()),'requestedBy':'phase2-locking-candidate'} for _ in range(2)]
        with ThreadPoolExecutor(max_workers=2) as pool:statuses=list(pool.map(lambda body:revoke(subject,body),operations))
        v.require(statuses==[204,204],'Concurrent distinct operations failed: '+str(statuses))
        rows=v.sql('SELECT operation_id,generation FROM pd_staging_risk.device_trust_revocations WHERE subject_id=%s ORDER BY generation DESC',(subject,))
        v.require([x[1] for x in rows]==[3,2,1],'Lost generation update or extra audit')
        by_id={x['operationId']:x for x in [op,*operations]};path='/subjects/'+subject+'/trusted-devices/revocations/completion'
        for ident,_ in rows[1:]:v.risk(path,by_id[ident],admin,409)
        v.risk(path,by_id[rows[0][0]],admin)
        v.risk('/trusted-devices',{'subjectId':subject,'deviceId':'phase2-stale-'+uuid.uuid4().hex,'trustGeneration':0},caller,409)
        record('Parallel reset idempotency/distinct-operation serialization; '+('existing' if seeded else 'new')+' subject',statuses=statuses,generations=[3,2,1])
    subject=str(uuid.uuid4());device='phase2-inflight-'+uuid.uuid4().hex
    generation=v.evaluate(subject,device,caller)['trustGeneration']
    op={'operationId':str(uuid.uuid4()),'requestedBy':'phase2-locking-candidate'}
    def registration():return v.request('https://risk:8443/internal/v1/trusted-devices','POST',{'subjectId':subject,'deviceId':device,'trustGeneration':generation},caller)[0]
    with ThreadPoolExecutor(max_workers=2) as pool:
        f=pool.submit(registration);g=pool.submit(revoke,subject,op);registered,revoked=f.result(),g.result()
    v.require(registered in (204,409) and revoked==204,'Registration/reset concurrency failed')
    v.require(v.sql("SELECT COUNT(*) FROM pd_staging_risk.known_devices WHERE subject_id=%s AND status='TRUSTED'",(subject,))[0][0]==0,'Old MFA attempt survived reset as TRUSTED')
    v.risk('/subjects/'+subject+'/trusted-devices/revocations/completion',op,admin)
    v.risk('/trusted-devices',{'subjectId':subject,'deviceId':device,'trustGeneration':generation},caller,409)
    record('Registration racing reset cannot preserve or recreate old-generation trust',registration_status=registered,revoke_status=revoked)
    v.require(v.sql("SELECT checksum,success FROM pd_staging_risk.flyway_schema_history WHERE version='5'")[0]==(661092940,1),'V5 changed')
    browser_setup()
    with v.sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-proxy-server'])
        ctx=browser.new_context(ignore_https_errors=False);responses=[]
        from urllib.parse import urlsplit
        ctx.on('response',lambda r:responses.append({'path':urlsplit(r.url).path,'status':r.status}) if urlsplit(r.url).path.startswith('/api/') else None)
        page,ctx,t,flow=v.login(browser,v.accounts['student_a'],ctx)
        v.require(flow=='verified OTP','Candidate did not preserve actual MFA')
        page.wait_for_load_state('networkidle')
        v.require(any(x['path']=='/api/students/me/scores' and x['status']==200 for x in responses),'Candidate browser own-grade read failed')
        v.api('/api/admin/users',t['access_token'],expected=403)
        browser.close()
    record('Candidate real Keycloak Risk SPI/OTP/PKCE, own grades, STUDENT403 and V5 preserved',browser_api_statuses=responses)


if __name__=='__main__':
    try:main()
    except Exception as e:
        r={'status':'FAIL','type':type(e).__name__,'line':traceback.extract_tb(e.__traceback__)[-1].lineno}
        if type(e) is RuntimeError:r['reason']=str(e)
        (v.RESULTS/'locking-failure.json').write_text(json.dumps(r,indent=2)+'\n');print('FAIL '+json.dumps(r),flush=True);raise SystemExit(1)
