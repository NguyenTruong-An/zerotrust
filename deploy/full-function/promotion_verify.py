"""Real HTTPS/service/browser checks inside ONLY the disposable restore core.
Credentials/OTP/recovery codes stay in memory. Synthetic continuity fixtures are
private; no real accounts or protected source volumes are mounted.
"""
import datetime as dt
import hashlib
import json
from pathlib import Path
import time
import traceback
import uuid
from urllib.parse import quote
import verify as v
import phase2_security as security

FIXTURE=Path('/fixtures/continuity.json')
STAGE='initial'


def credential_hashes():
    return {k:hashlib.sha256(repr(v.credential_snapshot(a['id'])).encode()).hexdigest() for k,a in v.accounts.items()}


def continuity(f):
    expected=f.get('after_mutation')
    if not expected:return
    subject=f['low_subject'];caller=v.service_token('zerotrust-risk-caller')
    state=v.sql('SELECT generation,pending_operation_id FROM pd_staging_risk.subject_device_trust WHERE subject_id=%s',(subject,))[0]
    v.require(list(state)==expected['state'],'Generation/pending changed during container operation')
    v.require(v.sql('SELECT COUNT(*) FROM pd_staging_risk.device_trust_revocations WHERE subject_id=%s',(subject,))[0][0]==expected['audit_count'],'Reset audit changed')
    v.require(v.sql("SELECT COUNT(*) FROM pd_staging_risk.known_devices WHERE subject_id=%s AND status='TRUSTED'",(subject,))[0][0]==0,'Revoked trust revived')
    denied=v.evaluate(subject,f['low_device'],caller)
    v.require(denied['decision']=='DENY' and 'MFA_RESET_IN_PROGRESS' in denied['reasons'],'Pending deny lost')
    v.risk('/trusted-devices',{'subjectId':subject,'deviceId':f['low_device'],'trustGeneration':0},caller,409)
    v.require(credential_hashes()==f['credential_hashes'],'Existing credentials changed')


def main(mode):
    global STAGE
    result={'status':'PASS','mode':mode,'V5':661092940,'evaluations':[],'public_browser_geoip':'NOT_VERIFIED_PRIVATE_DOCKER_PEER'}
    caller=v.service_token('zerotrust-risk-caller')
    v.require(v.sql("SELECT checksum,success FROM pd_staging_risk.flyway_schema_history WHERE version='5'")[0]==(661092940,1),'V5 changed')
    if mode.startswith('internal-'):
        # The external ingress is deliberately STOPPED. Direct service TLS/CRL
        # and scoped service JWT checks cannot accidentally reopen user traffic.
        f=json.loads(FIXTURE.read_text());continuity(f)
        status,health=v.request('https://risk:8443/actuator/health')
        v.require(status==200 and health.get('status')=='UP','Internal TLS Risk health failed')
        subject=str(uuid.uuid4());device='maintenance-check-'+uuid.uuid4().hex
        v.history(subject,caller);first=v.evaluate(subject,device,caller)
        v.require(first['decision']=='STEP_UP_MFA','Mandatory MFA bypassed during maintenance')
        result.update(TLS_CRL=True,scoped_service_JWT=True,continuity=True,credential_hashes_unchanged=True,
            ingress_required=False,authentication_browser='REUSED_PHASE23A_RECEIPT')
        if mode=='internal-promoted':
            v.risk('/trusted-devices',{'subjectId':subject,'deviceId':device,'trustGeneration':first['trustGeneration']},caller)
            geo=v.evaluate(subject,device,caller,'8.8.8.8')
            v.require(geo['riskScore']==12.5 and geo['decision']=='ALLOW','Maintenance GeoIP/B0 mismatch')
            result['geoip_network_contribution']=12.5
    elif mode=='prepare':
        subject=str(uuid.uuid4());device='controller-fixture-'+uuid.uuid4().hex
        v.history(subject,caller);initial=v.evaluate(subject,device,caller)
        v.risk('/trusted-devices',{'subjectId':subject,'deviceId':device,'trustGeneration':initial['trustGeneration']},caller)
        f={'low_subject':subject,'low_device':device,'credential_hashes':credential_hashes(),'browser_steps':{}}
        FIXTURE.write_text(json.dumps(f));result['prepared_synthetic_continuity']=True
    elif mode=='mutate':
        f=json.loads(FIXTURE.read_text());subject=f['low_subject'];admin=v.service_token('zerotrust-portal-risk-admin')
        v.risk('/subjects/'+subject+'/trusted-devices/revocations',{'operationId':str(uuid.uuid4()),'requestedBy':'authorized-disposable-controller-rehearsal'},admin)
        f['after_mutation']={'state':list(v.sql('SELECT generation,pending_operation_id FROM pd_staging_risk.subject_device_trust WHERE subject_id=%s',(subject,))[0]),
            'audit_count':v.sql('SELECT COUNT(*) FROM pd_staging_risk.device_trust_revocations WHERE subject_id=%s',(subject,))[0][0]}
        FIXTURE.write_text(json.dumps(f));continuity(f)
        result.update(current_generation=f['after_mutation']['state'][0],pending=True,audit_count=f['after_mutation']['audit_count'],credential_hashes_unchanged=True)
    else:
        f=json.loads(FIXTURE.read_text()) if FIXTURE.exists() else {'browser_steps':{}}
        continuity(f)
        STAGE='TLS service JWT and B0 fixtures'
        subject=str(uuid.uuid4());device='controller-check-'+uuid.uuid4().hex;v.history(subject,caller)
        first=v.evaluate(subject,device,caller);v.require(first['decision']=='STEP_UP_MFA','Mandatory MFA bypassed')
        v.risk('/trusted-devices',{'subjectId':subject,'deviceId':device,'trustGeneration':first['trustGeneration']},caller)
        low=v.evaluate(subject,device,caller)
        medium=v.evaluate(subject,'new-medium-'+uuid.uuid4().hex,caller,'203.0.113.201')
        geo=v.evaluate(subject,device,caller,'8.8.8.8')
        high_subject=str(uuid.uuid4());v.history(high_subject,caller,2)
        for _ in range(5):v.risk('/authentication-failures',{'eventId':str(uuid.uuid4()),'subjectId':high_subject,'sourceIp':'203.0.113.202'},caller)
        high=v.evaluate(high_subject,'new-high-'+uuid.uuid4().hex,caller,'203.0.113.202')
        v.require(low['riskScore']==0 and low['decision']=='ALLOW','LOW changed')
        v.require(medium['riskScore']==40 and medium['decision']=='STEP_UP_MFA','MEDIUM changed')
        v.require(high['riskScore']==77.5 and high['decision']=='DENY','HIGH changed')
        v.require(geo['riskScore']==12.5,'Network contribution changed')
        result['evaluations']=[{'case':k,'evaluation_id':x['evaluationId'],'score':x['riskScore'],'decision':x['decision']} for k,x in
            [('mandatory',first),('LOW',low),('MEDIUM',medium),('HIGH',high),('GeoIP-public-service-context',geo)]]
        STAGE='native browser OTP/PKCE and ADMIN/STUDENT authorization'
        security.browser_setup()
        with v.sync_playwright() as p:
            browser=p.chromium.launch(headless=True,args=['--no-proxy-server'])
            for key in ('student_a','admin'):
                step=int(time.time())//30
                if f['browser_steps'].get(key)==step:time.sleep(31-int(time.time())%30)
                page,ctx,tokens,flow=v.login(browser,v.accounts[key]);v.require(flow=='verified OTP','Browser did not perform actual OTP')
                page.wait_for_load_state('networkidle')
                if key=='student_a':
                    v.api('/api/students/me/scores',tokens['access_token']);v.api('/api/admin/users',tokens['access_token'],expected=403)
                else:v.api('/api/admin/users',tokens['access_token'])
                f['browser_steps'][key]=int(time.time())//30;ctx.close()
            result.update(OTP=True,PKCE='S256',STUDENT_own_grades=200,STUDENT_admin=403,ADMIN_users=200)
            # Run one new Recovery Code login after actual promotion. No flow edit
            # or owner account reset; the actor is freshly disposable.
            if mode=='promoted' and not f.get('recovery_verified'):
                STAGE='new disposable actor enrollment and Recovery Code'
                token=v.service_token('zerotrust-provisioner');actor=security.fixture('STUDENT',token)
                realm=security.kc('DoAn',token=token)
                executions=security.kc('DoAn/authentication/flows/'+quote(realm['browserFlow'],safe='')+'/executions',token=token)
                (v.RESULTS/'runtime-after.json').write_text(json.dumps({'executions':executions}))
                a=security.start_login(browser,actor);enrolled,codes=security.finish(a);tokens=security.redeem(a,'executor-disposable-enrollment')
                v.require(enrolled and len(codes)>=1,'Recovery enrollment missing')
                v.request(v.ISSUER+'/protocol/openid-connect/logout','POST',{'client_id':'zerotrust-spa','refresh_token':tokens['refresh_token']},form=True)
                b=security.start_login(browser,actor);security.use_recovery(b,codes[0],True);security.redeem(b,'executor-recovery-success')
                v.require(v.sql("SELECT COUNT(*) FROM pd_staging_risk.known_devices WHERE subject_id=%s AND status='TRUSTED'",(actor['id'],))[0][0]>=1,'Recovery did not register trust after real MFA')
                f['recovery_verified']=True;result['Recovery_Code']='REAL_NATIVE_PASS'
            else:result['Recovery_Code']='REUSED_THIS_REHEARSAL' if f.get('recovery_verified') else 'REUSED_PHASE2_RECEIPT'
            browser.close()
        if 'credential_hashes' in f:v.require(credential_hashes()==f['credential_hashes'],'Existing credentials changed')
        FIXTURE.write_text(json.dumps(f));result['continuity']=bool(f.get('after_mutation'))
    (v.RESULTS/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print('PASS scoped controller '+mode+' verification; secrets withheld',flush=True)


if __name__=='__main__':
    import sys
    try:main(sys.argv[1])
    except Exception as exc:
        result={'status':'FAIL','stage':STAGE,'type':type(exc).__name__,'line':traceback.extract_tb(exc.__traceback__)[-1].lineno}
        if type(exc) is RuntimeError:result['reason']=str(exc)
        (v.RESULTS/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        print('FAIL scoped controller verification '+json.dumps(result),flush=True);raise SystemExit(1)
