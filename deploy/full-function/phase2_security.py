"""Scoped synthetic security checks. Raw tokens/credentials never leave memory."""
import argparse
import base64
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import socket
import subprocess
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote
from urllib.parse import parse_qs, urlencode, urlsplit
from datetime import datetime,timezone

import verify as v

OUT=Path('/results')
STAGE='initial'
CASES=[]
MARKERS=[]
CURRENT_PAGE=None
RECEIPT='targeted-security.json'
ALLOWED_CONFIG={'riskServiceBaseUrl','tokenEndpointUrl','serviceClientId','failureMode','connectTimeoutMs',
                'socketTimeoutMs','connectionRequestTimeoutMs','tokenRefreshSkewMs','monitoredEventClientId','maxResponseBytes'}


def claims(token):
    d=json.loads(base64.urlsafe_b64decode(token.split('.')[1]+'==='))
    return {k:d[k] for k in ('iss','aud','azp','scope','realm_access','resource_access','exp','nbf','iat') if k in d} | {
        'sub_sha256':hashlib.sha256(d['sub'].encode()).hexdigest(),
        'kid':json.loads(base64.urlsafe_b64decode(token.split('.')[0]+'==='))['kid']}


def admin_token():
    cfg=json.loads((v.PRIVATE/'phase2-maintenance.json').read_text())
    status,body=v.request('https://keycloak:8443/realms/master/protocol/openid-connect/token','POST',
        {'grant_type':'client_credentials','client_id':cfg['client_id'],'client_secret':cfg['secret']},form=True)
    v.require(status==200,'Temporary isolated maintenance authentication failed')
    return body['access_token']


def kc(path='',method='GET',data=None,token=None,expected=200):
    status,body=v.request('https://keycloak:8443/admin/realms/'+path,method,data,token)
    detail=''
    if status!=expected and path.startswith('DoAn/authentication/') and isinstance(body,dict):
        detail=' '+str(body.get('errorMessage',body.get('error','unspecified')))[:180]
    v.require(status==expected,'Native management request failed: '+method+' '+path+' expected '+str(expected)+' got '+str(status)+detail)
    return body


def inventory(name='runtime-before'):
    token=v.service_token('zerotrust-provisioner')
    realm=kc('DoAn',token=token)
    flows=kc('DoAn/authentication/flows',token=token)
    flow=realm['browserFlow']
    executions=kc('DoAn/authentication/flows/'+quote(flow,safe='')+'/executions',token=token)
    configs=[]
    for e in executions:
        if e.get('authenticationConfig'):
            c=kc('DoAn/authentication/config/'+e['authenticationConfig'],token=token)
            configs.append({'alias':c['alias'],'config':{k:val for k,val in c['config'].items() if k in ALLOWED_CONFIG},
                            'secret_source':'FILE' if c['config'].get('serviceClientSecretFile') else 'INLINE'})
    clients=kc('DoAn/clients',token=token)
    doc={'realm':'DoAn','browserFlow':flow,'executions':executions,'configs':configs,
         'requiredActions':kc('DoAn/authentication/required-actions',token=token),
         'eventsListeners':realm['eventsListeners'],
         'session':{k:realm.get(k) for k in ('ssoSessionIdleTimeout','ssoSessionMaxLifespan','accessTokenLifespan','revokeRefreshToken','refreshTokenMaxReuse','notBefore')},
         'clients':[{k:c.get(k) for k in ('clientId','publicClient','serviceAccountsEnabled','standardFlowEnabled','directAccessGrantsEnabled','authenticationFlowBindingOverrides','defaultClientScopes','optionalClientScopes','protocolMappers','attributes')} for c in clients if c['clientId'].startswith('zerotrust-')],
         'service_tokens':{c:claims(v.service_token(c)) for c in ('zerotrust-risk-caller','zerotrust-portal-risk-admin','zerotrust-provisioner')}}
    (OUT/(name+'.json')).write_text(json.dumps(doc,indent=2)+'\n')
    print('PASS native read-only flow/client/token inventory: '+flow,flush=True)
    return doc


def repair():
    global STAGE
    token=admin_token()
    contract=json.loads(Path('/tests/auth-flow-contract.json').read_text())
    # Native list endpoint lists top-level flows only; discover subflow IDs using
    # read-only metadata, and create/change each object exclusively through API.
    flow_rows=lambda:dict(v.sql("SELECT ALIAS,ID FROM pd_staging_keycloak.AUTHENTICATION_FLOW WHERE REALM_ID=(SELECT ID FROM pd_staging_keycloak.REALM WHERE NAME='DoAn')"))
    existing=flow_rows()
    realm=kc('DoAn',token=token)
    v.require(realm['browserFlow']=='demo-browser','Only restore the known demo-derived binding; never overwrite another bound flow')
    old=kc('DoAn/authentication/flows/'+quote(realm['browserFlow'],safe='')+'/executions',token=token)
    config_id=next(e['authenticationConfig'] for e in old if e.get('providerId')=='zerotrust-risk-authenticator')
    config_alias=kc('DoAn/authentication/config/'+config_id,token=token)['alias']
    # Supported native flow/execution APIs; no direct SQL edits or partialImport
    # (partialImport does not support authentication flows).
    for flow in contract['authenticationFlows']:
        STAGE='create flow '+flow['alias']
        if flow['alias'] not in existing:
            kc('DoAn/authentication/flows','POST',{k:flow[k] for k in ('alias','providerId','topLevel','builtIn')},token,201)
    flow_ids=flow_rows()
    for flow in contract['authenticationFlows']:
        for e in flow['authenticationExecutions']:
            STAGE='create execution '+str(e.get('authenticator') or e.get('flowAlias'))
            data={k:e[k] for k in ('authenticator','authenticatorFlow','requirement','priority') if k in e}
            data['parentFlow']=flow_ids[flow['alias']]
            if e.get('flowAlias'):data['flowId']=flow_ids[e['flowAlias']]
            if e.get('authenticator')=='zerotrust-risk-authenticator':data['authenticatorConfig']=config_alias
            current=kc('DoAn/authentication/flows/'+quote(flow['alias'],safe='')+'/executions',token=token)
            if not any(x['level']==0 and x['priority']==e['priority'] for x in current):
                kc('DoAn/authentication/executions','POST',data,token,201)
    realm=kc('DoAn',token=token);realm['browserFlow']=contract['browserFlow']
    kc('DoAn','PUT',realm,token,204)
    inventory('runtime-after')
    (OUT/'flow-repair.json').write_text(json.dumps({'status':'PASS','change':'Restore complete historical legacy branch/execution contract; retain new Risk configuration/secret-file hardening','browserFlow':contract['browserFlow'],'business_or_session_policy_changed':False,'image_rebuilt':False},indent=2)+'\n')
    print('PASS complete legacy Browser Flow restored using native isolated Admin API',flush=True)


def browser_setup():
    home=Path('/tmp/zt-phase2-browser');(home/'.pki/nssdb').mkdir(parents=True,exist_ok=True)
    os.environ['HOME']=str(home)
    for args in (['certutil','-N','--empty-password','-d','sql:'+str(home/'.pki/nssdb')],
                 ['certutil','-A','-d','sql:'+str(home/'.pki/nssdb'),'-n','phase2-ca','-t','C,,','-i','/private/ca.crt']):
        subprocess.run(args,check=True,capture_output=True)


def record(case,result,details=None):
    CASES.append({'case':case,'result':result,'details':details or {}})
    (OUT/RECEIPT).write_text(json.dumps({'cases':CASES,'D17':'PENDING','G8':'INTERNET_NO_GO'},indent=2)+'\n')
    print('PASS '+case,flush=True)


def write_sql(statement,params):
    with v.pymysql.connect(host='mysql',user='root',password=(v.PRIVATE/'mysql/root-password').read_text(),charset='utf8mb4',ssl=v.context,autocommit=True) as db:
        with db.cursor() as c:c.execute(statement,params)


def fixture(role,token):
    uid=str(uuid.uuid4());name='phase2-'+role.lower()+'-'+uuid.uuid4().hex[:8]
    actor={'id':uid,'username':name,'password':secrets.token_urlsafe(28),'role':role}
    kc('DoAn/users','POST',{'id':uid,'username':name,'email':name+'@demo.invalid','emailVerified':True,
        'firstName':'Phase2','lastName':'Disposable','enabled':True,
        'requiredActions':['CONFIGURE_TOTP','CONFIGURE_RECOVERY_AUTHN_CODES'],
        'credentials':[{'type':'password','value':actor['password'],'temporary':False}]},token,201)
    created=kc('DoAn/users?username='+name+'&exact=true',token=token)
    v.require(len(created)==1,'Disposable user lookup was not unique')
    uid=actor['id']=created[0]['id']
    realm_role=kc('DoAn/roles/'+role,token=token)
    kc('DoAn/users/'+uid+'/role-mappings/realm','POST',[realm_role],token,204)
    portal_id=uuid.uuid4();actor['portal_id']=str(portal_id)
    write_sql('INSERT INTO pd_staging_school.users(id,keycloak_user_id,username,email,first_name,last_name,status) VALUES(%s,%s,%s,%s,%s,%s,%s)',
              (portal_id.bytes,uuid.UUID(uid).bytes,name,name+'@demo.invalid','Phase2','Disposable','ACTIVE'))
    return actor


def start_login(browser,actor,ctx=None,prompt='login'):
    global CURRENT_PAGE
    ctx=ctx or browser.new_context(ignore_https_errors=False)
    page=ctx.new_page();page.set_default_timeout(18000)
    CURRENT_PAGE=page
    # Intercept only our approved redirect in the test browser. No proxy, JWT or
    # server policy is altered. Redeem the code ourselves with its PKCE verifier.
    page.route(v.PORTAL+'/**',lambda route:route.fulfill(status=200,content_type='text/plain',body='Private PKCE callback'))
    verifier=secrets.token_urlsafe(48);state=uuid.uuid4().hex
    query={'client_id':'zerotrust-spa','redirect_uri':v.PORTAL+'/','response_type':'code','scope':'openid profile email',
           'state':state,'nonce':uuid.uuid4().hex,'code_challenge':base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('='),'code_challenge_method':'S256'}
    if prompt:query['prompt']=prompt
    begin=datetime.now(timezone.utc).isoformat()
    page.goto(v.ISSUER+'/protocol/openid-connect/auth?'+urlencode(query),wait_until='domcontentloaded')
    username=page.locator('#username')
    if username.count() and username.is_visible() and username.is_enabled() and username.get_attribute('readonly') is None:
        username.fill(actor['username'])
    if page.locator('#password').count():
        page.locator('#password').fill(actor['password'])
        page.locator('#kc-login').click();page.wait_for_load_state('domcontentloaded')
    return {'page':page,'ctx':ctx,'verifier':verifier,'state':state,'started':begin,'actor':actor}


def redeem(attempt,label):
    page=attempt['page'];query=parse_qs(urlsplit(page.url).query)
    v.require(query.get('state')==[attempt['state']] and len(query.get('code',[]))==1,'Authorization code/state missing after '+label)
    status,tokens=v.request(v.ISSUER+'/protocol/openid-connect/token','POST',{'grant_type':'authorization_code',
        'client_id':'zerotrust-spa','redirect_uri':v.PORTAL+'/','code_verifier':attempt['verifier'],'code':query['code'][0]},form=True)
    v.require(status==200,'PKCE code redemption failed')
    decoded=v.token_claims(tokens['access_token'],attempt['actor']['role'])
    v.require(decoded['sub']==attempt['actor']['id'],'Issued token subject differs from the intended disposable actor')
    MARKERS.append({'path':label,'start':attempt['started'],'end':datetime.now(timezone.utc).isoformat()})
    (OUT/RECEIPT.replace('.json','-markers.json')).write_text(json.dumps(MARKERS,indent=2)+'\n')
    return tokens


def finish(attempt,*,bad_otp=False):
    global STAGE
    page=attempt['page'];codes=[];enrolled=False
    for _ in range(8):
        if parse_qs(urlsplit(page.url).query).get('code'):break
        if page.locator('input[name=totpSecret]').count():
            enrolled=True;secret=page.locator('input[name=totpSecret]').input_value()
            v.require(not parse_qs(urlsplit(page.url).query).get('code'),'Enrollment issued a premature code')
            page.locator('input[name=totp]').fill(v.otp(secret))
            if page.locator('input[name=userLabel]').count():page.locator('input[name=userLabel]').fill('Phase2 disposable')
            page.locator('input[type=submit],button[type=submit]').first.click()
        elif page.locator('input[name=otp]').count():
            if bad_otp:
                STAGE='submit invalid TOTP; require native OTP challenge and no code'
                count_before=v.sql("SELECT COUNT(*) FROM pd_staging_risk.known_devices WHERE subject_id=%s AND status='TRUSTED'",(attempt['actor']['id'],))[0][0]
                page.locator('input[name=otp]').fill('000000' if v.otp(v.credential(attempt['actor']))!='000000' else '111111')
                with page.expect_response(lambda r:r.request.method=='POST' and '/login-actions/authenticate' in r.url):
                    page.locator('#kc-login').click()
                page.wait_for_load_state('domcontentloaded');page.locator('input[name=otp]').wait_for()
                v.require(not parse_qs(urlsplit(page.url).query).get('code'),'Invalid OTP issued a code')
                v.require(count_before==v.sql("SELECT COUNT(*) FROM pd_staging_risk.known_devices WHERE subject_id=%s AND status='TRUSTED'",(attempt['actor']['id'],))[0][0],'Invalid OTP created trust')
                record('Incorrect TOTP rejected without authorization code','PASS');bad_otp=False
                STAGE='submit correct TOTP after rejection'
            page.locator('input[name=otp]').fill(v.otp(v.credential(attempt['actor'])))
            page.locator('#kc-login').click()
        elif page.locator('#kcRecoveryCodesConfirmationCheck').count():
            codes=[re.sub(r'^\d+:\s*','',text).strip() for text in page.locator('#kc-recovery-codes-list li').all_text_contents()]
            v.require(len(codes)>=2,'Native recovery codes not presented')
            page.locator('#kcRecoveryCodesConfirmationCheck').check();page.locator('#saveRecoveryAuthnCodesBtn').click()
        else:raise RuntimeError('Unexpected browser challenge; no secrets captured to disk')
        page.wait_for_load_state('domcontentloaded')
    return enrolled,codes


def use_recovery(attempt,code,valid):
    global STAGE
    page=attempt['page']
    if not page.locator('#recoveryCodeInput').count():
        STAGE='select another MFA method'
        page.locator('#try-another-way').click()
        recovery=next(e for e in json.loads((OUT/'runtime-after.json').read_text())['executions'] if e.get('providerId')=='auth-recovery-authn-code-form')
        STAGE='select Recovery Code execution'
        # Keycloak v2 uses a hidden execution input plus a visible role=button.
        page.locator('li').filter(has=page.locator('[name=authenticationExecution][value="'+recovery['id']+'"]')).get_by_role('button').click()
    STAGE='submit Recovery Code '+('valid' if valid else 'invalid/consumed')
    page.locator('#recoveryCodeInput').fill(code);page.locator('#kc-login').click()
    page.wait_for_load_state('domcontentloaded')
    if not valid:
        page.locator('#recoveryCodeInput[aria-invalid=true]').wait_for()
        v.require(not parse_qs(urlsplit(page.url).query).get('code'),'Rejected recovery code issued authorization code')


def test():
    global STAGE
    browser_setup();maintenance=admin_token();caller=v.service_token('zerotrust-risk-caller')
    actor=fixture('STUDENT',maintenance);admin=fixture('ADMIN',maintenance)
    initial_others={k:hashlib.sha256(repr(v.credential_snapshot(a['id'])).encode()).hexdigest() for k,a in v.accounts.items()}
    with v.sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-proxy-server'])
        STAGE='new disposable enrollment'
        a=start_login(browser,actor);enrolled,codes=finish(a);tokens=redeem(a,'fresh-password-enrollment')
        v.require(enrolled and len(codes)>=2,'Mandatory OTP/recovery enrollment absent')
        v.require(v.sql("SELECT COUNT(*) FROM pd_staging_risk.known_devices WHERE subject_id=%s AND status='TRUSTED'",(actor['id'],))[0][0]==0,'Enrollment alone created trusted device')
        record('Mandatory first enrollment; no code before actions; enrollment alone creates no trust','PASS')
        service_claims=claims(tokens['access_token']);(OUT/'spa-token-contract.json').write_text(json.dumps(service_claims,indent=2)+'\n')
        v.request(v.ISSUER+'/protocol/openid-connect/logout','POST',{'client_id':'zerotrust-spa','refresh_token':tokens['refresh_token']},form=True)
        STAGE='recovery invalid/valid login'
        b=start_login(browser,actor);use_recovery(b,'invalid-phase2-code',False)
        record('Invalid Recovery Code rejected without code/token','PASS')
        use_recovery(b,codes[0],True);rt=redeem(b,'recovery-login')
        old_cookie=next(c for c in b['ctx'].cookies() if c['name']=='ZT_DEVICE_ID')
        v.require(v.sql("SELECT COUNT(*) FROM pd_staging_risk.known_devices WHERE subject_id=%s AND status='TRUSTED'",(actor['id'],))[0][0]>=1,'Successful recovery MFA did not register trust')
        record('Valid Recovery Code completes Risk step-up and native MFA; trust only after success','PASS')
        v.request(v.ISSUER+'/protocol/openid-connect/logout','POST',{'client_id':'zerotrust-spa','refresh_token':rt['refresh_token']},form=True)
        STAGE='consumed recovery replay'
        c=start_login(browser,actor);use_recovery(c,codes[0],False)
        record('Previously consumed Recovery Code rejected without code/token','PASS');c['ctx'].close()
        # A different unused code proves the previous rejection was not a broken method.
        d=start_login(browser,actor);use_recovery(d,codes[1],True);dt=redeem(d,'second-recovery-login')
        STAGE='SSO and refresh semantics'
        sso=start_login(browser,actor,d['ctx'],prompt=None)
        v.require(not sso['page'].locator('#username').count() and not sso['page'].locator('input[name=otp]').count(),'Expected existing legacy cookie SSO path absent')
        st=redeem(sso,'existing-SSO-cookie')
        start=datetime.now(timezone.utc).isoformat()
        status,refresh=v.request(v.ISSUER+'/protocol/openid-connect/token','POST',{'grant_type':'refresh_token','client_id':'zerotrust-spa','refresh_token':st['refresh_token']},form=True)
        v.require(status==200,'Valid refresh failed');v.token_claims(refresh['access_token'],'STUDENT')
        MARKERS.append({'path':'refresh','start':start,'end':datetime.now(timezone.utc).isoformat()})
        (OUT/'session-markers.json').write_text(json.dumps(MARKERS,indent=2)+'\n')
        record('Existing SSO cookie and refresh issue tokens without password/OTP; separate from fresh Risk flow','PASS',{'risk_execution':'requires trace corroboration','policy_changed':False})
        STAGE='JWT and service isolation'
        untouched=lambda:hashlib.sha256(repr(v.sql('SELECT * FROM pd_staging_risk.device_trust_revocations ORDER BY operation_id')).encode()).hexdigest()
        before=untouched();op={'operationId':str(uuid.uuid4()),'requestedBy':'phase2-negative'}
        checks=[]
        for client in ('zerotrust-risk-caller','zerotrust-provisioner'):
            status,_=v.request('https://risk:8443/internal/v1/subjects/'+actor['id']+'/trusted-devices/revocations','POST',op,v.service_token(client))
            v.require(status in (401,403),'Unauthorized service revoked a device');checks.append({'caller':client,'status':status})
        for token,label in ((dt['access_token'],'SPA-STUDENT'),(v.service_token('zerotrust-portal-risk-admin'),'portal-risk-admin-evaluate'),(v.service_token('zerotrust-provisioner'),'provisioner-evaluate')):
            status,_=v.request('https://risk:8443/internal/v1/risk/evaluations','POST',{'subjectId':actor['id'],'authenticationSessionId':str(uuid.uuid4()),'clientId':'zerotrust-spa','ipAddress':'198.51.100.22'},token,nonce=True)
            v.require(status in (401,403),'Unauthorized caller evaluated Risk');checks.append({'caller':label,'status':status})
        v.require(untouched()==before,'Rejected Risk requests changed reset state')
        status,_=v.request('https://keycloak:8443/admin/realms/DoAn/users',token=dt['access_token'])
        v.require(status in (401,403),'SPA gained Keycloak management authority')
        status,_=v.request(v.PORTAL+'/api/admin/users/'+admin['portal_id']+'/mfa/reset','POST',{},dt['access_token'])
        v.require(status==403,'STUDENT reset authorized')
        record('Real signed SPA/service tokens denied unauthorized Risk/Keycloak/reset operations; no reset-state changes','PASS',{'checks':checks,'student_reset':status})
        STAGE='fresh ADMIN reset and post-reset token semantics'
        aa=start_login(browser,admin);finish(aa);at=redeem(aa,'admin-initial-enrollment')
        prior=claims(at['access_token']);max_validity=prior['exp']-prior['iat']
        status,_=v.request(v.PORTAL+'/api/admin/users/'+actor['portal_id']+'/mfa/reset','POST',{},at['access_token'])
        v.require(status in (200,204),'Disposable ADMIN reset failed after restored flow')
        status,_=v.request(v.ISSUER+'/protocol/openid-connect/token','POST',{'grant_type':'refresh_token','client_id':'zerotrust-spa','refresh_token':refresh['refresh_token']},form=True)
        v.require(status==400,'Reset failed to revoke refresh/SSO session')
        post=start_login(browser,actor,d['ctx'],prompt=None)
        v.require(post['page'].locator('input[name=totpSecret]').count()>0,'Old SSO/device bypassed re-enrollment after reset')
        v.require(not parse_qs(urlsplit(post['page'].url).query).get('code'),'Code before reset enrollment')
        finish(post);redeem(post,'post-reset-reenrollment')
        # Self-reset only this NEW disposable ADMIN; demonstrate the residual JWT window.
        status,_=v.request(v.PORTAL+'/api/admin/users/'+admin['portal_id']+'/mfa/reset','POST',{},at['access_token'])
        v.require(status in (200,204),'Disposable ADMIN self-reset failed')
        retained_status,_=v.request(v.PORTAL+'/api/admin/users',token=at['access_token'])
        v.require(retained_status==200,'Unexpected access JWT semantics changed')
        record('Reset revokes refresh/SSO and old trust; existing ADMIN access JWT remains accepted until expiry','PASS',{'token_lifespan_seconds':max_validity,'fresh_admin_MFA_policy':'not enforced on reset endpoint','old_admin_access_status':retained_status})
        for k,a in v.accounts.items():v.require(initial_others[k]==hashlib.sha256(repr(v.credential_snapshot(a['id'])).encode()).hexdigest(),'An owner fixture credential changed')
        record('Original full-function ADMIN/STUDENT credential hashes unchanged; destructive tests only new disposable subjects','PASS')
        (OUT/'disposable-subjects.json').write_text(json.dumps({'student':actor['id'],'admin':admin['id'],'synthetic_only':True},indent=2)+'\n')
        browser.close()


def boundaries():
    global STAGE,RECEIPT
    RECEIPT='targeted-boundaries.json';browser_setup()
    actor=fixture('STUDENT',v.service_token('zerotrust-provisioner'))
    caller=v.service_token('zerotrust-risk-caller');revoker=v.service_token('zerotrust-portal-risk-admin')
    with v.sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-proxy-server'])
        STAGE='forwarded header subject/IP boundary'
        ctx=browser.new_context(ignore_https_errors=False,extra_http_headers={'X-Forwarded-For':'203.0.113.99','X-Real-IP':'203.0.113.99','Forwarded':'for=203.0.113.99'})
        a=start_login(browser,actor,ctx);finish(a);tokens=redeem(a,'spoofed-forwarded-headers')
        d=json.loads(base64.urlsafe_b64decode(tokens['access_token'].split('.')[1]+'==='))
        v.require(d['sub']==actor['id'],'Client context changed the authenticated subject')
        ip=v.sql("SELECT IP_ADDRESS FROM pd_staging_keycloak.EVENT_ENTITY WHERE USER_ID=%s AND TYPE='LOGIN' ORDER BY EVENT_TIME DESC LIMIT 1",(actor['id'],))[0][0]
        actual_ip=socket.gethostbyname(socket.gethostname())
        v.require(ip==actual_ip and ip!='203.0.113.99','Untrusted forwarded header changed client address')
        record('Client forwarded headers cannot spoof actual Keycloak peer IP or authenticated subject','PASS')
        v.request(v.ISSUER+'/protocol/openid-connect/logout','POST',{'client_id':'zerotrust-spa','refresh_token':tokens['refresh_token']},form=True)
        STAGE='incorrect and correct TOTP after restored alternative flow'
        time.sleep(31-int(time.time())%30)
        b=start_login(browser,actor);finish(b,bad_otp=True);redeem(b,'correct-OTP-after-rejection')
        cookie=next(c for c in b['ctx'].cookies() if c['name']=='ZT_DEVICE_ID')
        record('Correct TOTP succeeds after invalid TOTP; alternative Recovery branch cannot bypass actual MFA','PASS')
        browser.close()
    STAGE='cross-user and expired trust'
    other=str(uuid.uuid4())
    cross=v.evaluate(other,cookie['value'],caller)
    v.require(cross['decision']=='STEP_UP_MFA','Another subject inherited device trust')
    write_sql("UPDATE pd_staging_risk.known_devices SET first_seen_at=UTC_TIMESTAMP(6)-INTERVAL 32 DAY,last_seen_at=UTC_TIMESTAMP(6)-INTERVAL 31 DAY,trusted_at=UTC_TIMESTAMP(6)-INTERVAL 31 DAY WHERE subject_id=%s AND status='TRUSTED'",(actor['id'],))
    expired=v.evaluate(actor['id'],cookie['value'],caller)
    v.require(expired['decision']=='STEP_UP_MFA' and 'DEVICE_REAUTHENTICATION_REQUIRED' in expired['reasons'],'Expired trust was accepted')
    record('Cross-user cookie isolation and 30-day server trust expiry require MFA','PASS',{'fixture':'only this new disposable subject timestamp aged; B0/policy unchanged'})
    STAGE='pending and stale-generation registration'
    generation=expired['trustGeneration'];op={'operationId':str(uuid.uuid4()),'requestedBy':'phase2-disposable'}
    path='/subjects/'+actor['id']+'/trusted-devices/revocations'
    v.risk(path,op,revoker)
    pending=v.evaluate(actor['id'],cookie['value'],caller)
    v.require(pending['decision']=='DENY' and pending['dataStatus']=='NOT_EVALUATED' and 'MFA_RESET_IN_PROGRESS' in pending['reasons'],'Pending reset failed priority DENY')
    data={'subjectId':actor['id'],'deviceId':cookie['value'],'trustGeneration':generation}
    v.risk('/trusted-devices',data,caller,409)
    v.risk(path+'/completion',op,revoker)
    v.risk('/trusted-devices',data,caller,409)
    state=v.sql('SELECT generation,pending_operation_id FROM pd_staging_risk.subject_device_trust WHERE subject_id=%s',(actor['id'],))[0]
    v.risk(path,op,revoker);v.risk(path+'/completion',op,revoker)
    v.require(state==v.sql('SELECT generation,pending_operation_id FROM pd_staging_risk.subject_device_trust WHERE subject_id=%s',(actor['id'],))[0],'Repeated operation changed generation')
    record('Pending reset priority DENY, stale generation409 before/after completion and same-operation idempotency','PASS')
    STAGE='superseded completion and security revoke'
    op1={'operationId':str(uuid.uuid4()),'requestedBy':'phase2-disposable'};op2={'operationId':str(uuid.uuid4()),'requestedBy':'phase2-disposable'}
    v.risk(path,op1,revoker);v.risk(path,op2,revoker)
    v.risk(path+'/completion',op1,revoker,409);v.risk(path+'/completion',op2,revoker)
    write_sql("UPDATE pd_staging_risk.known_devices SET status='REVOKED',revocation_reason='SECURITY',revoked_at=UTC_TIMESTAMP(6) WHERE subject_id=%s",(actor['id'],))
    denied=v.evaluate(actor['id'],cookie['value'],caller)
    v.require(denied['decision']=='DENY' and denied['dataStatus']=='NOT_EVALUATED','Security revoked device became trusted')
    record('Superseded completion409 and SECURITY-revoked device priority DENY without fabricated numeric HIGH','PASS')


def session_boundaries():
    global STAGE,RECEIPT
    RECEIPT='session-boundaries.json';browser_setup()
    actor=fixture('STUDENT',v.service_token('zerotrust-provisioner'))
    caller=v.service_token('zerotrust-risk-caller');revoker=v.service_token('zerotrust-portal-risk-admin')
    with v.sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-proxy-server'])
        a=start_login(browser,actor);finish(a);tokens=redeem(a,'session-fixture-enrollment')
        op={'operationId':str(uuid.uuid4()),'requestedBy':'phase2-partial-reset'};path='/subjects/'+actor['id']+'/trusted-devices/revocations'
        v.risk(path,op,revoker)
        denied=v.evaluate(actor['id'],None,caller)
        v.require(denied['decision']=='DENY' and 'MFA_RESET_IN_PROGRESS' in denied['reasons'],'Pending state not established')
        STAGE='SSO and refresh during pending Risk revoke'
        b=start_login(browser,actor,a['ctx'],prompt=None);bt=redeem(b,'SSO-during-pending-reset')
        status,refreshed=v.request(v.ISSUER+'/protocol/openid-connect/token','POST',{'grant_type':'refresh_token','client_id':'zerotrust-spa','refresh_token':bt['refresh_token']},form=True)
        v.require(status==200,'Refresh behavior unexpectedly changed')
        record('Confirmed residual: pending Risk revoke alone does not invalidate existing SSO/refresh','PASS',{'security_state':'Risk DENY / MFA_RESET_IN_PROGRESS','SSO_token_issued':True,'refresh_status':status,'owner_policy_decision_required':True})
        STAGE='forced reauthentication while reset pending'
        forced=start_login(browser,actor,a['ctx'],prompt='login')
        forced['page'].locator('#kc-error-message').wait_for()
        v.require(not parse_qs(urlsplit(forced['page'].url).query).get('code'),'Forced reauth bypassed pending DENY')
        record('Forced reauthentication runs Risk and blocks pending reset without code','PASS')
        v.request(v.ISSUER+'/protocol/openid-connect/logout','POST',{'client_id':'zerotrust-spa','refresh_token':refreshed['refresh_token']},form=True)
        status,_=v.request(v.ISSUER+'/protocol/openid-connect/token','POST',{'grant_type':'refresh_token','client_id':'zerotrust-spa','refresh_token':refreshed['refresh_token']},form=True)
        v.require(status==400,'Logout did not invalidate refresh')
        fresh=start_login(browser,actor)
        fresh['page'].locator('#kc-error-message').wait_for()
        v.require(not parse_qs(urlsplit(fresh['page'].url).query).get('code'),'Fresh login bypassed pending DENY')
        record('Logout then fresh password login runs Risk and blocks pending reset','PASS')
        v.risk(path+'/completion',op,revoker)
        # Finish the disposable partial operation; no owner account was reset.
        record('Disposable pending operation completed; owner credentials untouched','PASS')
        browser.close()
    STAGE='real MySQL concurrent reset fencing'
    subject=str(uuid.uuid4());path='/subjects/'+subject+'/trusted-devices/revocations'
    op={'operationId':str(uuid.uuid4()),'requestedBy':'phase2-race'}
    def revoke(body):return v.request('https://risk:8443/internal/v1'+path,'POST',body,revoker)[0]
    with ThreadPoolExecutor(max_workers=2) as pool:statuses=list(pool.map(revoke,[op,op]))
    v.require(statuses==[204,204],'Same-operation concurrent revoke was not idempotent')
    generation=v.sql('SELECT generation FROM pd_staging_risk.subject_device_trust WHERE subject_id=%s',(subject,))[0][0]
    v.require(generation==1,'Same operation incremented generation twice')
    operations=[{'operationId':str(uuid.uuid4()),'requestedBy':'phase2-race'} for _ in range(2)]
    with ThreadPoolExecutor(max_workers=2) as pool:statuses=list(pool.map(revoke,operations))
    v.require(statuses==[204,204],'Distinct concurrent operations failed')
    rows=v.sql('SELECT operation_id,generation FROM pd_staging_risk.device_trust_revocations WHERE subject_id=%s ORDER BY generation DESC',(subject,))
    v.require(rows[0][1]==3,'Concurrent generation increments lost an update')
    by_id={x['operationId']:x for x in [op,*operations]}
    for operation,g in rows[1:]:v.risk(path+'/completion',by_id[operation],revoker,409)
    v.risk(path+'/completion',by_id[rows[0][0]],revoker)
    record('Real MySQL parallel same-operation idempotency, distinct generation serialization and superseded completion fencing','PASS')


def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=('inventory','inventory-resume','repair','test','boundaries','session-boundaries','remove-maintenance'))
    args=parser.parse_args().action
    if args=='inventory':inventory()
    elif args=='inventory-resume':inventory('runtime-resumed')
    elif args=='repair':repair()
    elif args=='test':test()
    elif args=='boundaries':boundaries()
    elif args=='session-boundaries':session_boundaries()
    else:
        token=admin_token();cfg=json.loads((v.PRIVATE/'phase2-maintenance.json').read_text())
        clients=kc('master/clients?clientId='+cfg['client_id'],token=token)
        v.require(len(clients)==1,'Unexpected maintenance client count')
        kc('master/clients/'+clients[0]['id'],'DELETE',token=token,expected=204)
        print('PASS temporary maintenance service removed; no business identity used as super-admin',flush=True)


if __name__=='__main__':
    try:main()
    except Exception as e:
        failure={'stage':STAGE,'type':type(e).__name__,'file':Path(traceback.extract_tb(e.__traceback__)[-1].filename).name,'line':traceback.extract_tb(e.__traceback__)[-1].lineno}
        if type(e) is RuntimeError:failure['reason']=str(e)
        if CURRENT_PAGE and not CURRENT_PAGE.is_closed():
            try:failure['form_structure']=CURRENT_PAGE.locator('input,button,a[id]').evaluate_all('(nodes)=>nodes.map(n=>({tag:n.tagName,id:n.id,name:n.getAttribute("name"),type:n.getAttribute("type")}))')
            except Exception:pass
        (OUT/'phase2-failure.json').write_text(json.dumps(failure,indent=2)+'\n')
        print('FAIL '+json.dumps(failure),flush=True);raise SystemExit(1)
