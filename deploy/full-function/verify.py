"""Real HTTPS/browser/API acceptance against only the new synthetic profile.

Run in the disposable browser helper on zt-full-function-20261111_core.
Only /private from that profile is mounted. No screenshots, traces or token logs.
"""
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import ssl
import struct
import subprocess
import time
import traceback
import uuid
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, ProxyHandler

import pymysql
from playwright.sync_api import sync_playwright

PRIVATE=Path('/private')
RESULTS=Path('/results')
PORTAL='https://portal.full-function.test:39443'
AUTH='https://auth.full-function.test:39443'
ISSUER=AUTH+'/realms/DoAn'
accounts=json.loads((PRIVATE/'accounts.json').read_text())
context=ssl.create_default_context(cafile=str(PRIVATE/'ca-with-crl.pem'))
context.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN
opener=build_opener(ProxyHandler({}),HTTPSHandler(context=context))
passed=[]
stage='initialization'
last_page=None
RUN=uuid.uuid4().hex[:7]


def require(ok,text):
    if not ok:raise RuntimeError(text)


def record(text):
    passed.append(text)
    (RESULTS/'acceptance.json').write_text(json.dumps({'passed':passed,'D17':'PENDING','G8':'INTERNET_NO_GO'},indent=2)+'\n')
    print('PASS '+text,flush=True)


def sql(statement,params=None):
    with pymysql.connect(host='mysql',user='root',password=(PRIVATE/'mysql/root-password').read_text(),
                         charset='utf8mb4',ssl=context,connect_timeout=8) as db:
        with db.cursor() as cur:
            cur.execute(statement,params)
            return cur.fetchall()


def request(url,method='GET',data=None,token=None,form=False,nonce=False):
    headers={}
    if token:headers['Authorization']='Bearer '+token
    if nonce:headers['X-ZeroTrust-Risk-Request']=str(uuid.uuid4())
    if data is not None:
        headers['Content-Type']='application/x-www-form-urlencoded' if form else 'application/json'
        data=(urlencode(data) if form else json.dumps(data)).encode()
    try:
        response=opener.open(Request(url,data=data,headers=headers,method=method),timeout=20)
    except HTTPError as error:response=error
    body=response.read()
    try:body=json.loads(body) if body else None
    except ValueError:body=None
    return response.status,body


def api(path,token,method='GET',data=None,expected=200):
    status,body=request(PORTAL+path,method,data,token)
    require(status==expected,'API status mismatch: '+method+' '+path+' expected '+str(expected)+' got '+str(status))
    return body.get('data') if isinstance(body,dict) else None


def otp(raw):
    digest=hmac.digest(raw.encode(),struct.pack('>Q',int(time.time())//30),'sha1')
    offset=digest[-1]&15
    return f'{(int.from_bytes(digest[offset:offset+4],"big")&0x7fffffff)%1000000:06d}'


def credential(actor):
    rows=sql("SELECT SECRET_DATA FROM pd_staging_keycloak.CREDENTIAL WHERE USER_ID=%s AND TYPE='otp'",(actor['id'],))
    require(len(rows)==1,'OTP credential missing')
    return json.loads(rows[0][0])['value']


def token_claims(token,role):
    claims=json.loads(base64.urlsafe_b64decode(token.split('.')[1]+'==='))
    require(claims['iss']==ISSUER,'Wrong issuer')
    roles=claims.get('realm_access',{}).get('roles',[])
    require(role in roles and ('ADMIN' not in roles if role=='STUDENT' else True),'Wrong business role issued')
    require('kc-admin-api' not in claims.get('scope','').split(),'SPA received an Admin API scope')
    return claims


def login(browser,actor,ctx=None,expect_enrollment=False,expect_deny=False):
    global last_page
    ctx=ctx or browser.new_context(ignore_https_errors=False)
    page=ctx.new_page();page.set_default_timeout(25000)
    last_page=page
    issued=[]
    page.on('response',lambda r: issued.append(r.json()) if r.status==200 and urlsplit(r.url).path.endswith('/openid-connect/token') else None)
    page.goto(PORTAL,wait_until='domcontentloaded')
    page.get_by_role('button',name='Đăng nhập với Keycloak').click()
    page.wait_for_url(lambda u:urlsplit(u).hostname=='auth.full-function.test')
    query=parse_qs(urlsplit(page.url).query)
    require(query.get('code_challenge_method')==['S256'] and query.get('client_id')==['zerotrust-spa'],'OIDC/PKCE contract drift')
    page.locator('#username').fill(actor['username']);page.locator('#password').fill(actor['password'])
    page.locator('#kc-login,button[type=submit]').first.click()
    page.wait_for_load_state('domcontentloaded')
    if expect_deny:
        page.locator('#kc-error-message,#input-error').first.wait_for()
        require(not issued and urlsplit(page.url).hostname=='auth.full-function.test','HIGH issued token')
        return page,ctx,None,'denied'
    flow='password-only';new_secret=None
    for _ in range(8):
        if page.get_by_role('button',name='Đăng xuất',exact=True).count():break
        if page.locator('input[name=totpSecret]').count():
            require(not issued,'Token issued before required enrollment')
            flow='enrollment';new_secret=page.locator('input[name=totpSecret]').input_value()
            page.locator('input[name=totp]').fill(otp(new_secret))
            if page.locator('input[name=userLabel]').count():page.locator('input[name=userLabel]').fill('Full-function synthetic')
            page.locator('input[type=submit],button[type=submit]').first.click()
        elif page.locator('input[name=otp]').count():
            flow='verified OTP';page.locator('input[name=otp]').fill(otp(credential(actor)))
            page.locator('input[type=submit],button[type=submit]').first.click()
        elif page.get_by_role('checkbox').count():
            # Native recovery-code required action; secret values are never persisted/logged.
            page.get_by_role('checkbox').first.check()
            page.locator('input[type=submit],button[type=submit]').first.click()
        else:
            page.get_by_role('button',name='Đăng xuất',exact=True).wait_for()
        page.wait_for_load_state('domcontentloaded')
    page.get_by_role('button',name='Đăng xuất',exact=True).wait_for()
    require(bool(issued),'No OIDC access token')
    token_claims(issued[-1]['access_token'],actor['role'])
    require(not expect_enrollment or flow=='enrollment','Expected new OTP enrollment')
    return page,ctx,issued[-1],flow


def logout(page):
    page.get_by_role('button',name='Đăng xuất',exact=True).click()
    page.get_by_role('button',name='Đăng nhập với Keycloak').wait_for()
    page.close()


def service_token(client):
    doc=json.loads((PRIVATE/'installer/DoAn-realm.json').read_text())
    row=next(c for c in doc['clients'] if c['clientId']==client)
    status,body=request('https://keycloak:8443/realms/DoAn/protocol/openid-connect/token','POST',
                        {'grant_type':'client_credentials','client_id':client,'client_secret':row['secret']},form=True)
    require(status==200,'Service JWT not issued')
    return body['access_token']


def risk(path,data,token,expected=204):
    status,body=request('https://risk:8443/internal/v1'+path,'POST',data,token,nonce=path.endswith('/evaluations'))
    require(status==expected,'Risk API status mismatch '+path+' '+str(status))
    return body


def history(subject,token,offset=0):
    now=dt.datetime.now(dt.timezone.utc)
    for i in range(1,6):
        risk('/authentication-successes',{'eventId':str(uuid.uuid4()),'subjectId':subject,'clientId':'zerotrust-spa',
             'authenticatedAt':(now-dt.timedelta(weeks=i,days=offset)).isoformat()},token)


def evaluate(subject,device,token,ip='198.51.100.22'):
    return risk('/risk/evaluations',{'subjectId':subject,'authenticationSessionId':str(uuid.uuid4()),
                'clientId':'zerotrust-spa','ipAddress':ip,'userAgent':'Full-function synthetic test','deviceId':device},token,200)


def credential_snapshot(subject):
    return sql('SELECT TYPE,SECRET_DATA,CREDENTIAL_DATA FROM pd_staging_keycloak.CREDENTIAL WHERE USER_ID=%s ORDER BY TYPE,ID',(subject,))


def main():
    global stage
    RESULTS.mkdir(exist_ok=True)
    home=Path('/tmp/zt-full-browser');(home/'.pki/nssdb').mkdir(parents=True,exist_ok=True)
    os.environ['HOME']=str(home)
    for args in (['certutil','-N','--empty-password','-d','sql:'+str(home/'.pki/nssdb')],
                 ['certutil','-A','-d','sql:'+str(home/'.pki/nssdb'),'-n','full-synthetic-ca','-t','C,,','-i',str(PRIVATE/'ca.crt')]):
        subprocess.run(args,check=True,capture_output=True)
    stage='strict TLS and issuer'
    status,discovery=request(ISSUER+'/.well-known/openid-configuration')
    require(status==200 and discovery['issuer']==ISSUER,'Discovery mismatch')
    require(request(AUTH+'/admin/')[0]==404 and request(PORTAL+'/actuator/health')[0]==404,'Private management exposed')
    require(sql("SELECT checksum,success FROM pd_staging_risk.flyway_schema_history WHERE version='5'")[0]==(661092940,1),'V5 checksum drift')
    record('Strict TLS/CRL chain, DoAn issuer, private management boundary and V5 checksum')
    caller=service_token('zerotrust-risk-caller')
    provisioner=service_token('zerotrust-provisioner')
    claims=json.loads(base64.urlsafe_b64decode(provisioner.split('.')[1]+'==='))
    audience=claims.get('aud',[]);audience=[audience] if isinstance(audience,str) else audience
    require('kc-admin-api' in claims.get('scope','').split() and AUTH+'/admin/realms/DoAn' in audience,
            'Keycloak 26.8.2 provisioner scope/audience missing')
    require(request('https://keycloak:8443/admin/realms/DoAn/users/count',token=provisioner)[0]==200,
            'Scoped service identity cannot use native Admin API')
    record('Provisioner kc-admin-api scope/audience and native Admin API; no super-admin user')
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-proxy-server'])
        stage='ADMIN browser login'
        admin,admin_ctx,admin_tokens,admin_flow=login(browser,accounts['admin'])
        at=admin_tokens['access_token'];admin_claims=token_claims(at,'ADMIN')
        admin_subject=admin_claims.get('preferred_username') or admin_claims['sub']
        record('Real ADMIN browser PKCE, custom theme and MFA ('+admin_flow+')')
        admin.goto(PORTAL+'/admin/classes')
        admin.get_by_role('button',name='Tạo lớp',exact=True).wait_for()
        record('Standard frontend displays full ADMIN create controls')
        stage='ADMIN business writes'
        class_code='FULL_'+RUN.upper()
        cl=api('/api/admin/student-classes',at,'POST',{'classCode':class_code,'className':'Synthetic write class','department':'Computer Science','courseYears':'2026-2030'},201)
        empty=api('/api/admin/student-classes',at,'POST',{'classCode':'EMPTY_'+RUN,'className':'Disposable empty','department':'Computer Science','courseYears':'2026-2030'},201)
        api('/api/admin/student-classes/'+empty['id'],at,'DELETE',expected=204)
        sub=api('/api/admin/subjects',at,'POST',{'subjectCode':'FULL_'+RUN,'subjectName':'Synthetic subject','credits':3,'description':'Disposable'},201)
        temporary=api('/api/admin/subjects',at,'POST',{'subjectCode':'DELETE_'+RUN,'subjectName':'Delete fixture','credits':2},201)
        api('/api/admin/subjects/'+temporary['id'],at,'DELETE',expected=204)
        record('ADMIN real class and subject create/read/delete on disposable data')
        new_password=secrets.token_urlsafe(24)
        created_username='full-created-'+RUN
        student=api('/api/admin/students',at,'POST',{'username':created_username,'password':new_password,'email':RUN+'@demo.invalid','firstName':'Synthetic','lastName':'Created','studentCode':'FULL_'+RUN,'dateOfBirth':'2005-01-01','gender':'OTHER','classCode':class_code},201)
        api('/api/admin/students/'+student['id'],at,'PATCH',{'firstName':'Updated'})
        require(api('/api/admin/students/'+student['id'],at)['firstName']=='Updated','Student update did not persist')
        score=api('/api/admin/students/'+student['id']+'/scores',at,'POST',{'subjectId':sub['id'],'semester':1,'academicYear':'2026-2027','attendanceScore':8,'midtermScore':7,'finalScore':9},201)
        updated=api('/api/admin/scores/'+score['id'],at,'PATCH',{'attendanceScore':9,'midtermScore':8,'finalScore':9})
        require(float(updated['attendanceScore'])==9,'Score update value mismatch')
        api('/api/admin/scores/'+score['id'],at,'DELETE',expected=204)
        api('/api/admin/subjects/'+sub['id']+'/scores/batch',at,'POST',{'semester':1,'academicYear':'2026-2027','scores':[{'studentId':student['id'],'attendanceScore':9,'midtermScore':8,'finalScore':9}]})
        record('ADMIN real class/subject create-delete, student create-update and score create-update-delete/batch')
        stage='STUDENT ownership and authorization'
        a,ac,ta,_=login(browser,accounts['student_a'],expect_enrollment=True)
        b,bc,tb,_=login(browser,accounts['student_b'],expect_enrollment=True)
        for actor,t in ((accounts['student_a'],ta),(accounts['student_b'],tb)):
            token=t['access_token'];me=api('/api/students/me',token)
            own=sql('SELECT HEX(s.id) FROM pd_staging_school.students s JOIN pd_staging_school.users u ON u.id=s.user_id WHERE u.keycloak_user_id=UNHEX(%s)',(actor['id'].replace('-',''),))[0][0]
            require(me['id']==str(uuid.UUID(hex=own)),'Wrong STUDENT profile')
            require(len(api('/api/students/me/scores',token)['content'])==1,'Own grades not returned immediately after enrollment')
            api('/api/students/me/scores/summary',token)
            require(api('/api/students/me?userId='+student['id'],token)['id']==me['id'],'Ownership overridden by query')
            api('/api/admin/users',token,expected=403)
            api('/api/admin/students',token,'POST',{},403)
        target=next(u for u in api('/api/admin/users',at) if u['username']==accounts['student_b']['username'])
        api('/api/admin/users/'+target['id']+'/mfa/reset',ta['access_token'],'POST',expected=403)
        tampered=ta['access_token'][:-3]+'xyz'
        api('/api/students/me',tampered,expected=401)
        record('Both STUDENT first-login own grades/profile/summary; ADMIN writes/reset denied; altered JWT rejected')
        stage='MEDIUM OTP and trusted-device LOW'
        logout(b);bc.close();history(accounts['student_b']['id'],caller)
        # Avoid replaying a TOTP accepted during initial enrollment.
        time.sleep(31-int(time.time())%30)
        b,bc,tb,flow=login(browser,accounts['student_b'])
        require(flow=='verified OTP','New device did not step up')
        old_cookie=next(c for c in bc.cookies() if c['name']=='ZT_DEVICE_ID')
        require(sql("SELECT COUNT(*) FROM pd_staging_risk.known_devices WHERE subject_id=%s AND status='TRUSTED'",(accounts['student_b']['id'],))[0][0]>=1,'No trusted device after OTP')
        logout(b)
        b,_,tb,flow=login(browser,accounts['student_b'],bc)
        require(flow=='password-only','Trusted LOW unexpectedly forced OTP')
        record('Real browser MEDIUM/new-device OTP, trusted-device registration and LOW relogin without OTP')
        stage='ADMIN UI MFA reset'
        before_others={alias:credential_snapshot(accounts[alias]['id']) for alias in ('admin','student_a')}
        old_secret=credential(accounts['student_b'])
        generation=sql('SELECT generation FROM pd_staging_risk.subject_device_trust WHERE subject_id=%s',(accounts['student_b']['id'],))[0][0]
        admin.goto(PORTAL+'/admin/users')
        admin.get_by_role('button',name='Reset MFA cho '+accounts['student_b']['username'],exact=True).click()
        with admin.expect_response(lambda r:r.request.method=='POST' and r.url.endswith('/mfa/reset')) as response:
            admin.get_by_role('button',name='Xác nhận reset MFA',exact=True).click()
        require(response.value.status==204,'ADMIN UI reset failed')
        admin.get_by_role('status').filter(has_text='Đã reset MFA').wait_for()
        subject=accounts['student_b']['id']
        require(sql("SELECT COUNT(*) FROM pd_staging_keycloak.CREDENTIAL WHERE USER_ID=%s AND TYPE IN ('otp','recovery-authn-codes')",(subject,))[0][0]==0,'Old MFA credentials survived reset')
        actions={r[0] for r in sql('SELECT REQUIRED_ACTION FROM pd_staging_keycloak.USER_REQUIRED_ACTION WHERE USER_ID=%s',(subject,))}
        require({'CONFIGURE_TOTP','CONFIGURE_RECOVERY_AUTHN_CODES'}<=actions,'Enrollment required actions missing')
        row=sql('SELECT generation,pending_operation_id FROM pd_staging_risk.subject_device_trust WHERE subject_id=%s',(subject,))[0]
        require(row==(generation+1,None),'Trust generation/completion mismatch')
        audit=sql('SELECT requested_by,completed_at,revoked_count FROM pd_staging_risk.device_trust_revocations WHERE subject_id=%s ORDER BY revoked_at DESC LIMIT 1',(subject,))[0]
        require(audit[0]==admin_subject and audit[1] is not None and audit[2]>=1,'Reset audit missing/incorrect')
        require(sql("SELECT COUNT(*) FROM pd_staging_risk.known_devices WHERE subject_id=%s AND status='TRUSTED'",(subject,))[0][0]==0,'Trust not revoked')
        require(request(ISSUER+'/protocol/openid-connect/token','POST',{'grant_type':'refresh_token','client_id':'zerotrust-spa','refresh_token':tb['refresh_token']},form=True)[0]==400,'Old refresh token survived reset/logout')
        require(all(credential_snapshot(accounts[k]['id'])==v for k,v in before_others.items()),'Other accounts changed by reset')
        record('ADMIN UI -> API -> Risk revoke -> Keycloak OTP/recovery removal/logout -> completion/audit; other accounts unchanged')
        stage='Old trust replay and required re-enrollment'
        replay=browser.new_context(ignore_https_errors=False);replay.add_cookies([old_cookie])
        fresh,replay,new_tokens,flow=login(browser,accounts['student_b'],replay,expect_enrollment=True)
        require(credential(accounts['student_b'])!=old_secret,'OTP secret not replaced by enrollment')
        token_claims(new_tokens['access_token'],'STUDENT')
        api('/api/students/me/scores',new_tokens['access_token'])
        require(all(credential_snapshot(accounts[k]['id'])==v for k,v in before_others.items()),'Re-enrollment changed another user')
        record('Old Trusted Device cannot bypass new OTP/recovery enrollment; correctly scoped STUDENT token only after completion')
        stage='Real Risk API LOW/MEDIUM/HIGH'
        low=str(uuid.uuid4());history(low,caller)
        device='full-function-risk-disposable'
        first=evaluate(low,device,caller)
        require(first['decision']=='STEP_UP_MFA','Mandatory MFA not enforced')
        risk('/trusted-devices',{'subjectId':low,'deviceId':device,'trustGeneration':first['trustGeneration']},caller)
        require(evaluate(low,device,caller)['decision']=='ALLOW','LOW not ALLOW')
        require(evaluate(low,device,caller,'203.0.113.3')['decision']=='STEP_UP_MFA','MEDIUM not STEP_UP')
        created_subject=sql('SELECT u.keycloak_user_id FROM pd_staging_school.users u JOIN pd_staging_school.students s ON s.user_id=u.id WHERE s.id=UNHEX(%s)',(student['id'].replace('-',''),))[0][0]
        high_subject=str(uuid.UUID(bytes=created_subject));history(high_subject,caller,2)
        for _ in range(5):risk('/authentication-failures',{'eventId':str(uuid.uuid4()),'subjectId':high_subject,'sourceIp':'203.0.113.4'},caller)
        high=evaluate(high_subject,None,caller,'203.0.113.4')
        require(high['riskLevel']=='HIGH' and high['decision']=='DENY','HIGH not DENY')
        # The ordinary helper is not the high-risk network fixture. Browser HIGH is a
        # separate mandatory test-risk action using the real dedicated source address.
        record('Real service-JWT Risk API LOW/MEDIUM/HIGH; dedicated HIGH browser check follows separately')
        snapshot={'student_count':sql('SELECT COUNT(*) FROM pd_staging_school.students')[0][0],
                  'score_count':sql('SELECT COUNT(*) FROM pd_staging_school.scores')[0][0],
                  'v5':sql("SELECT checksum FROM pd_staging_risk.flyway_schema_history WHERE version='5'")[0][0],
                  'reset_generation':generation+1,'reset_subject':subject,
                  'low_subject':low,'low_device':device,'high_subject':high_subject}
        (RESULTS/'persistence-before.json').write_text(json.dumps(snapshot,indent=2)+'\n')
        browser.close()


if __name__=='__main__':
    try:main()
    except Exception as error:
        RESULTS.mkdir(exist_ok=True)
        # Error strings/call logs can contain filled credentials or URLs. Never persist them.
        failure={'stage':stage,'error_type':type(error).__name__,'passed':passed,
                 'line':traceback.extract_tb(error.__traceback__)[-1].lineno}
        if type(error) is RuntimeError:failure['reason']=str(error)
        if isinstance(error,pymysql.MySQLError) and error.args and isinstance(error.args[0],int):failure['mysql_code']=error.args[0]
        try:
            if last_page and not last_page.is_closed():
                failure['page_path']=urlsplit(last_page.url).path
                failure['input_names']=last_page.locator('input').evaluate_all('(xs)=>xs.map(x=>x.name)')
        except Exception:pass
        (RESULTS/'failure.json').write_text(json.dumps(failure,indent=2)+'\n')
        (RESULTS/('failure-'+RUN+'.json')).write_text(json.dumps(failure,indent=2)+'\n')
        print('FAIL stage='+stage+' type='+type(error).__name__+'; sensitive details withheld',flush=True)
        raise SystemExit(1)
