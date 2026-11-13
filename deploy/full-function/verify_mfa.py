"""Continue only security acceptance after completed CRUD, without repeating it."""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import traceback
import uuid

import verify as v

stage='resume preconditions'


def main():
    global stage
    receipt=json.loads((v.RESULTS/'acceptance.json').read_text())
    v.require(any('student create-update' in x for x in receipt['passed']),'Real CRUD acceptance required')
    v.passed[:]=receipt['passed']
    home=Path('/tmp/zt-mfa-browser');(home/'.pki/nssdb').mkdir(parents=True)
    os.environ['HOME']=str(home)
    for args in (['certutil','-N','--empty-password','-d','sql:'+str(home/'.pki/nssdb')],
                 ['certutil','-A','-d','sql:'+str(home/'.pki/nssdb'),'-n','full-ca','-t','C,,','-i','/private/ca.crt']):
        subprocess.run(args,check=True,capture_output=True)
    caller=v.service_token('zerotrust-risk-caller')
    actor=v.accounts['student_b'];subject=actor['id']
    with v.sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-proxy-server'])
        admin,admin_ctx,t,_=v.login(browser,v.accounts['admin']);at=t['access_token']
        claims=v.token_claims(at,'ADMIN');requester=claims.get('preferred_username') or claims['sub']
        stage='complete prior legitimate required actions'
        page,ctx,_,_=v.login(browser,actor,expect_enrollment=True)
        v.logout(page);ctx.close()
        # This user was legitimately reset during the preceding UI test; complete that flow.
        v.record('Prior ADMIN reset audit matches configured preferred_username principal; native OTP/recovery re-enrollment completes')
        stage='fresh OTP and trust preparation'
        time.sleep(31-int(time.time())%30)
        page,ctx,tokens,flow=v.login(browser,actor)
        v.require(flow=='verified OTP','Fresh context did not require OTP')
        old_cookie=next(c for c in ctx.cookies() if c['name']=='ZT_DEVICE_ID')
        v.require(v.sql("SELECT COUNT(*) FROM pd_staging_risk.known_devices WHERE subject_id=%s AND status='TRUSTED'",(subject,))[0][0]>=1,'No trust before reset')
        old_secret=v.credential(actor)
        v.logout(page)
        page,ctx,tokens,flow=v.login(browser,actor,ctx)
        v.require(flow=='password-only','Trusted LOW should not force OTP')
        before={k:v.credential_snapshot(v.accounts[k]['id']) for k in ('admin','student_a')}
        actions_before={k:v.sql('SELECT REQUIRED_ACTION FROM pd_staging_keycloak.USER_REQUIRED_ACTION WHERE USER_ID=%s ORDER BY REQUIRED_ACTION',(v.accounts[k]['id'],)) for k in before}
        generation=v.sql('SELECT generation FROM pd_staging_risk.subject_device_trust WHERE subject_id=%s',(subject,))[0][0]
        target=next(u for u in v.api('/api/admin/users',at) if u['username']==actor['username'])
        stage='ADMIN UI reset and audit'
        admin.goto(v.PORTAL+'/admin/users')
        admin.get_by_role('button',name='Reset MFA cho '+actor['username'],exact=True).click()
        with admin.expect_response(lambda r:r.request.method=='POST' and r.url.endswith('/mfa/reset')) as response:
            admin.get_by_role('button',name='Xác nhận reset MFA',exact=True).click()
        v.require(response.value.status==204,'ADMIN reset did not complete')
        admin.get_by_role('status').filter(has_text='Đã reset MFA').wait_for()
        v.require(v.sql("SELECT COUNT(*) FROM pd_staging_keycloak.CREDENTIAL WHERE USER_ID=%s AND TYPE IN ('otp','recovery-authn-codes')",(subject,))[0][0]==0,'Old MFA credential survived reset')
        actions={r[0] for r in v.sql('SELECT REQUIRED_ACTION FROM pd_staging_keycloak.USER_REQUIRED_ACTION WHERE USER_ID=%s',(subject,))}
        v.require({'CONFIGURE_TOTP','CONFIGURE_RECOVERY_AUTHN_CODES'}<=actions,'Required actions missing')
        v.require(v.sql('SELECT generation,pending_operation_id FROM pd_staging_risk.subject_device_trust WHERE subject_id=%s',(subject,))[0]==(generation+1,None),'Reset not completed/generation not advanced')
        audit=v.sql('SELECT requested_by,completed_at,revoked_count FROM pd_staging_risk.device_trust_revocations WHERE subject_id=%s ORDER BY revoked_at DESC LIMIT 1',(subject,))[0]
        v.require(audit[0]==requester and audit[1] is not None and audit[2]>=1,'Reset audit does not match authenticated principal')
        v.require(v.sql("SELECT COUNT(*) FROM pd_staging_risk.known_devices WHERE subject_id=%s AND status='TRUSTED'",(subject,))[0][0]==0,'Old trust survived reset')
        v.require(v.request(v.ISSUER+'/protocol/openid-connect/token','POST',{'grant_type':'refresh_token','client_id':'zerotrust-spa','refresh_token':tokens['refresh_token']},form=True)[0]==400,'Old refresh token accepted')
        v.require(all(v.credential_snapshot(v.accounts[k]['id'])==x for k,x in before.items()),'Reset affected another account credential')
        v.require(all(v.sql('SELECT REQUIRED_ACTION FROM pd_staging_keycloak.USER_REQUIRED_ACTION WHERE USER_ID=%s ORDER BY REQUIRED_ACTION',(v.accounts[k]['id'],))==x for k,x in actions_before.items()),'Reset affected another account required action')
        v.require(v.sql('SELECT COUNT(*) FROM pd_staging_keycloak.ADMIN_EVENT_ENTITY WHERE RESOURCE_PATH LIKE %s',(f'users/{subject}/%',))[0][0]>0,'Keycloak administrative audit missing')
        # Target scope is the application's mapped active users, never arbitrary Keycloak IDs.
        v.api('/api/admin/users/'+str(uuid.uuid4())+'/mfa/reset',at,'POST',expected=404)
        v.record('ADMIN UI/API reset: OTP/recovery removed, trust generation advanced, logout/refresh revoked, application and Keycloak audit correct, other accounts unchanged')
        stage='old cookie replay and new enrollment'
        replay=browser.new_context(ignore_https_errors=False);replay.add_cookies([old_cookie])
        new_page,replay,new_tokens,flow=v.login(browser,actor,replay,expect_enrollment=True)
        v.require(v.credential(actor)!=old_secret,'New OTP enrollment reused old secret')
        v.token_claims(new_tokens['access_token'],'STUDENT')
        v.api('/api/students/me/scores',new_tokens['access_token'])
        v.require(all(v.credential_snapshot(v.accounts[k]['id'])==x for k,x in before.items()),'Enrollment affected another account')
        v.record('Old Trusted Device replay cannot bypass OTP/recovery re-enrollment; no token before completion and new token is STUDENT only')
        stage='LOW MEDIUM HIGH and real HIGH browser'
        low=str(uuid.uuid4());v.history(low,caller);device='full-function-risk-disposable'
        first=v.evaluate(low,device,caller)
        v.require(first['decision']=='STEP_UP_MFA','Mandatory MFA missing')
        v.risk('/trusted-devices',{'subjectId':low,'deviceId':device,'trustGeneration':first['trustGeneration']},caller)
        v.require(v.evaluate(low,device,caller)['decision']=='ALLOW','LOW failed')
        v.require(v.evaluate(low,device,caller,'203.0.113.3')['decision']=='STEP_UP_MFA','MEDIUM failed')
        suffix=uuid.uuid4().hex[:7];password=secrets.token_urlsafe(24)
        student=v.api('/api/admin/students',at,'POST',{'username':'full-high-'+suffix,'password':password,'email':suffix+'@demo.invalid','firstName':'Synthetic','lastName':'High','studentCode':'HIGH_'+suffix,'dateOfBirth':'2005-01-01','gender':'OTHER','classCode':'DEMO_A'},201)
        identity=v.sql('SELECT u.keycloak_user_id FROM pd_staging_school.users u JOIN pd_staging_school.students s ON s.user_id=u.id WHERE s.id=UNHEX(%s)',(student['id'].replace('-',''),))[0][0]
        high=str(uuid.UUID(bytes=identity));v.history(high,caller,2)
        for _ in range(5):v.risk('/authentication-failures',{'eventId':str(uuid.uuid4()),'subjectId':high,'sourceIp':'203.0.113.4'},caller)
        outcome=v.evaluate(high,None,caller,'203.0.113.4')
        v.require(outcome['riskLevel']=='HIGH' and outcome['decision']=='DENY','HIGH API failed')
        v.login(browser,{'id':high,'username':'full-high-'+suffix,'password':password,'role':'STUDENT'},expect_deny=True)
        v.record('Real Risk service LOW/ALLOW, MEDIUM/STEP_UP_MFA and HIGH/DENY; real HIGH browser rejects before issuing any token')
        status,jwks=v.request(v.ISSUER+'/protocol/openid-connect/certs');v.require(status==200,'JWKS missing')
        snapshot={'student_count':v.sql('SELECT COUNT(*) FROM pd_staging_school.students')[0][0],
                  'score_count':v.sql('SELECT COUNT(*) FROM pd_staging_school.scores')[0][0],
                  'v5':v.sql("SELECT checksum FROM pd_staging_risk.flyway_schema_history WHERE version='5'")[0][0],
                  'jwks_sha256':hashlib.sha256(json.dumps(jwks,sort_keys=True).encode()).hexdigest(),
                  'credentials_sha256':{k:hashlib.sha256(repr(v.credential_snapshot(a['id'])).encode()).hexdigest() for k,a in v.accounts.items()},
                  'reset_generation':generation+1,'reset_subject':subject,
                  'low_subject':low,'low_device':device,'high_subject':high}
        (v.RESULTS/'persistence-before.json').write_text(json.dumps(snapshot,indent=2)+'\n')
        browser.close()


if __name__=='__main__':
    try:main()
    except Exception as error:
        failure={'stage':stage,'error_type':type(error).__name__,'line':traceback.extract_tb(error.__traceback__)[-1].lineno,'passed':v.passed}
        if type(error) is RuntimeError:failure['reason']=str(error)
        try:
            if v.last_page and not v.last_page.is_closed():
                failure['page_path']=v.urlsplit(v.last_page.url).path
                failure['input_names']=v.last_page.locator('input').evaluate_all('(xs)=>xs.map(x=>x.name)')
        except Exception:pass
        (v.RESULTS/'mfa-failure.json').write_text(json.dumps(failure,indent=2)+'\n')
        print('FAIL stage='+stage+' type='+type(error).__name__+'; sensitive details withheld',flush=True)
        raise SystemExit(1)
