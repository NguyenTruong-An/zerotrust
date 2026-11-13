"""Synthetic-only native D10 evidence. Credentials/tokens/cookies remain in process memory."""
import base64,datetime as dt,hashlib,hmac,json,os,secrets,ssl,struct,subprocess,sys,time,uuid,http.server,threading,collections,re
from pathlib import Path
from urllib.parse import urlencode,urlsplit,parse_qs
from urllib.request import Request,build_opener,HTTPSHandler,ProxyHandler
from urllib.error import HTTPError
from concurrent.futures import ThreadPoolExecutor
import pymysql
from playwright.sync_api import sync_playwright
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes
PRIVATE=Path('/private');OUT=Path('/results');PORTAL='https://portal.full-function.test:39443';ISSUER='https://auth.full-function.test:39443/realms/DoAn'
TLS=ssl.create_default_context(cafile=str(PRIVATE/'ca-with-crl.pem'));TLS.verify_flags|=ssl.VERIFY_CRL_CHECK_CHAIN
OPENER=build_opener(ProxyHandler({}),HTTPSHandler(context=TLS));CASES=[];STAGE='initial';TOKENS={}
ACTORS=json.loads((PRIVATE/'accounts.json').read_text());SECRETS=json.loads((PRIVATE/'d10-service-credentials.json').read_text());LAST_FACTOR={};START_BUCKET=int(time.time())//30
def require(value,reason):
    if not value:raise RuntimeError(reason)
def record(case,details=None):
    CASES.append({'case':case,'status':'PASS','details':details or {}});save();print('PASS '+case,flush=True)
def save():
    (OUT/'native.json').write_text(json.dumps({'scope':'fresh disposable synthetic users; no active data','cases':CASES,'D10':'UNRESOLVED_UNTIL_DEPLOYED_ACCEPTANCE','D17':'PENDING','G8':'INTERNET_NO_GO'},indent=2)+'\n')
def request(url,method='GET',data=None,token=None,form=False):
    headers={'Accept':'application/json'}
    if token:headers['Authorization']='Bearer '+token
    if data is not None:
        headers['Content-Type']='application/x-www-form-urlencoded' if form else 'application/json';data=(urlencode(data) if form else json.dumps(data)).encode()
    try:response=OPENER.open(Request(url,data=data,headers=headers,method=method),timeout=12)
    except HTTPError as error:response=error
    body=response.read(65537);require(len(body)<=65536,'RESPONSE_BOUND')
    try:body=json.loads(body) if body else None
    except ValueError:body=None
    return response.status,body
def sql(statement,params=None):
    require(statement.lstrip().upper().startswith('SELECT'),'READ_ONLY_SQL_REQUIRED')
    with pymysql.connect(host='mysql',user='root',password=(PRIVATE/'mysql/root-password').read_text(),charset='utf8mb4',ssl=TLS,connect_timeout=8) as db:
        with db.cursor() as cursor:cursor.execute(statement,params);return cursor.fetchall()
def service(name):
    if name in TOKENS and TOKENS[name][1]>time.time()+20:return TOKENS[name][0]
    secret=SECRETS.get(name)
    if name=='zerotrust-provisioner':
        props=dict(line.split('=',1) for line in (PRIVATE/'backend/application.properties').read_text().splitlines() if '=' in line and not line.startswith('#'));secret=props['keycloak.admin.client-secret']
    status,body=request('https://keycloak:8443/realms/DoAn/protocol/openid-connect/token','POST',{'grant_type':'client_credentials','client_id':name,'client_secret':secret},form=True)
    require(status==200 and isinstance(body,dict) and 'access_token'in body,'MACHINE_TOKEN_UNAVAILABLE_'+str(status));TOKENS[name]=(body['access_token'],time.time()+body['expires_in']);return body['access_token']
def authority(path,body,name='zerotrust-issuer-security',expected=200):
    status,result=request('https://risk:8443/internal/v1/security/'+path,'POST',body,service(name));require(status==expected,'AUTHORITY_'+path+'_'+str(status));return result
def maintenance():
    key='fixture-master'
    if key in TOKENS and TOKENS[key][1]>time.time()+20:return TOKENS[key][0]
    credential=json.loads((PRIVATE/'d10-maintenance.json').read_text())
    status,body=request('https://keycloak:8443/realms/master/protocol/openid-connect/token','POST',{'grant_type':'client_credentials','client_id':credential['client_id'],'client_secret':credential['secret']},form=True)
    require(status==200,'FIXTURE_MAINTENANCE_AUTH');TOKENS[key]=(body['access_token'],time.time()+body['expires_in']);return body['access_token']
def admin(path,method='GET',body=None,expected=200):
    status,result=request('https://keycloak:8443/admin/realms/DoAn'+path,method,body,maintenance());require(status==expected,'FIXTURE_ADMIN_'+str(status));return result
def write_school(statement,args):
    require(statement.startswith(('INSERT INTO pd_staging_school.users','INSERT INTO pd_staging_school.students','INSERT INTO pd_staging_school.scores')),'SYNTHETIC_INSERT_SCOPE')
    with pymysql.connect(host='mysql',user='root',password=(PRIVATE/'mysql/root-password').read_text(),charset='utf8mb4',ssl=TLS,autocommit=True) as db:
        with db.cursor() as cursor:cursor.execute(statement,args)
class FaultProxy(http.server.BaseHTTPRequestHandler):
    fail_confirmation=False;fail_effect_response=False;hold_retry=False;released=threading.Event();admissions=collections.Counter();injected_confirmation=False;injected_response=False
    def log_message(self,*args):pass
    def do_POST(self):
        try:
            require(self.path.startswith('/internal/v1/security/') or self.path=='/realms/DoAn/d10-security/effects','PROXY_SCOPE')
            size=int(self.headers.get('Content-Length','0'));require(0<=size<16384,'PROXY_BODY_BOUND');data=self.rfile.read(size);body=json.loads(data)
            action=body.get('action');effect=body.get('effectId')
            if self.path.endswith('/native-confirmation') and action=='CREDENTIAL_MUTATION' and FaultProxy.fail_confirmation:
                FaultProxy.fail_confirmation=False;FaultProxy.injected_confirmation=True;self.send_response(503);self.end_headers();return
            native=self.path.endswith('/d10-security/effects')
            if native and action=='CREDENTIAL_MUTATION' and FaultProxy.hold_retry and FaultProxy.injected_response:
                FaultProxy.released.wait(45)
            target=('https://keycloak:8443' if native else 'https://risk:8443')+self.path
            status,result=request(target,'POST',body,self.headers.get('Authorization','')[7:])
            if self.path.endswith('/native-admission') and status==204:FaultProxy.admissions[effect]+=1
            if native and action=='CREDENTIAL_MUTATION' and FaultProxy.fail_effect_response:
                FaultProxy.fail_effect_response=False;FaultProxy.injected_response=True;status=503;result=None
            payload=json.dumps(result).encode() if result is not None else b''
            self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
        except Exception:
            try:self.send_response(503);self.end_headers()
            except Exception:pass
def start_proxy():
    server=http.server.ThreadingHTTPServer(('0.0.0.0',8444),FaultProxy);server.daemon_threads=True
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain('/private/d10-proxy/server.crt','/private/d10-proxy/server.key');server.socket=context.wrap_socket(server.socket,server_side=True)
    threading.Thread(target=server.serve_forever,daemon=True).start();return server
def fresh_actors():
    """Each run creates synthetic identities and School rows; never resets an existing identity."""
    global ACTORS
    templates=ACTORS;actors={}
    for key,template in templates.items():
        actor={'id':str(uuid.uuid4()),'username':'d10-'+key.replace('_','-')+'-'+uuid.uuid4().hex[:8],'password':secrets.token_urlsafe(32),'role':template['role'],'otp':secrets.token_hex(16)}
        body={'id':actor['id'],'username':actor['username'],'enabled':True,'email':actor['username']+'@demo.invalid','emailVerified':True,'firstName':'D10','lastName':'Synthetic','credentials':[{'type':'password','value':actor['password'],'temporary':False},{'type':'otp','userLabel':'d10-native-fixture','secretData':json.dumps({'value':actor['otp']}),'credentialData':json.dumps({'subType':'totp','digits':6,'counter':0,'period':30,'algorithm':'HmacSHA1'})}]}
        admin('/users','POST',body,201);rows=admin('/users?username='+actor['username']+'&exact=true');require(len(rows)==1,'NEW_SYNTHETIC_IDENTITY_UNIQUE');actor['id']=rows[0]['id']
        roles=[admin('/roles/'+actor['role']),admin('/roles/offline_access')];admin('/users/'+actor['id']+'/role-mappings/realm','POST',roles,204)
        require(sql("SELECT COUNT(*) FROM pd_staging_keycloak.CREDENTIAL WHERE USER_ID=%s AND TYPE='otp'",(actor['id'],))[0][0]==1,'NATIVE_CREATE_OTP_UNSUPPORTED')
        portal_id=uuid.uuid4();actor['portal_id']=str(portal_id)
        write_school('INSERT INTO pd_staging_school.users(id,keycloak_user_id,username,email,first_name,last_name,status) VALUES(%s,%s,%s,%s,%s,%s,%s)',(portal_id.bytes,uuid.UUID(actor['id']).bytes,actor['username'],actor['username']+'@demo.invalid','D10','Synthetic','ACTIVE'))
        if actor['role']=='STUDENT':
            student=uuid.uuid4()
            write_school('INSERT INTO pd_staging_school.students(id,user_id,class_id,student_code,date_of_birth,gender) SELECT %s,%s,class_id,%s,date_of_birth,gender FROM pd_staging_school.students WHERE user_id=(SELECT id FROM pd_staging_school.users WHERE keycloak_user_id=%s)',(student.bytes,portal_id.bytes,'D10-'+uuid.uuid4().hex[:10],uuid.UUID(template['id']).bytes))
            write_school('INSERT INTO pd_staging_school.scores(id,student_id,subject_id,attendance_score,midterm_score,final_score,total_score,grade,semester,academic_year) SELECT UUID_TO_BIN(UUID()),%s,subject_id,attendance_score,midterm_score,final_score,total_score,grade,semester,academic_year FROM pd_staging_school.scores WHERE student_id=(SELECT id FROM pd_staging_school.students WHERE user_id=(SELECT id FROM pd_staging_school.users WHERE keycloak_user_id=%s))',(student.bytes,uuid.UUID(template['id']).bytes))
        actors[key]=actor
    ACTORS=actors
    clients=admin('/clients?clientId=zerotrust-spa');scope=next(s for s in admin('/client-scopes') if s['name']=='offline_access')
    admin('/clients/'+clients[0]['id']+'/optional-client-scopes/'+scope['id'],'PUT',expected=204)
def api(path,token,status=200,base=PORTAL,method='GET'):
    actual,body=request(base+path,method,token=token);require(actual==status,'API_'+path+'_'+str(actual)+'_EXPECTED_'+str(status));return body
def reset_wait(portal_id,subject,token):
    status,_=request(PORTAL+'/api/admin/users/'+portal_id+'/mfa/reset','POST',token=token)
    require(status in (204,503),'RESET_STATUS_'+str(status))
    end=time.monotonic()+45
    while time.monotonic()<end:
        row=sql("SELECT stage FROM pd_staging_risk.security_operations WHERE subject_id=%s AND operation_kind='MFA_RESET' ORDER BY created_at DESC LIMIT 1",(subject,))
        if row and row[0][0]=='COMPLETED':return status
        time.sleep(.25)
    raise RuntimeError('RESET_COMPLETION_PENDING')
def claims(token):
    parts=token.split('.');header=json.loads(base64.urlsafe_b64decode(parts[0]+'==='));payload=json.loads(base64.urlsafe_b64decode(parts[1]+'==='))
    require(header['alg']=='RS256' and payload['iss']==ISSUER,'TOKEN_IDENTITY')
    status,jwks=request(ISSUER+'/protocol/openid-connect/certs');require(status==200,'JWKS')
    key=next(k for k in jwks['keys'] if k['kid']==header['kid']);number=lambda v:int.from_bytes(base64.urlsafe_b64decode(v+'==='),'big')
    rsa.RSAPublicNumbers(number(key['e']),number(key['n'])).public_key().verify(base64.urlsafe_b64decode(parts[2]+'==='),(parts[0]+'.'+parts[1]).encode(),padding.PKCS1v15(),hashes.SHA256())
    require(payload.get('zt_sec_ver')==1 and isinstance(payload.get('zt_sec_epoch'),int) and payload.get('sid')==payload.get('zt_sec_sid'),'STRICT_CLAIMS')
    return payload
def ctx(claim):return {'subjectId':claim['sub'],'sessionId':claim['sid'],'clientId':claim['azp'],'epoch':claim['zt_sec_epoch']}
def otp(raw,counter=None):
    digest=hmac.digest(raw.encode(),struct.pack('>Q',int(time.time())//30 if counter is None else counter),'sha1');offset=digest[-1]&15
    return f'{(int.from_bytes(digest[offset:offset+4],"big")&0x7fffffff)%1000000:06d}'
def refresh(token):return request(ISSUER+'/protocol/openid-connect/token','POST',{'grant_type':'refresh_token','refresh_token':token,'client_id':'zerotrust-spa'},form=True)
def setup_browser():
    home=Path('/tmp/d10-browser-'+uuid.uuid4().hex);db=home/'.pki/nssdb';db.mkdir(parents=True);os.environ['HOME']=str(home)
    subprocess.run(['certutil','-N','--empty-password','-d','sql:'+str(db)],capture_output=True,check=True,timeout=15)
    subprocess.run(['certutil','-A','-d','sql:'+str(db),'-n','d10-ca','-t','C,,','-i','/private/ca.crt'],capture_output=True,check=True,timeout=15)
def authorize(browser,actor,context=None,proof=None,prompt='login',exchange=True,wrong_otp=False,allow_credentials=True,scope='openid',native_action=None,new_password=None,enroll=False,recovery_code=None,invalid_recovery=False):
    context=context or browser.new_context(ignore_https_errors=False);page=context.new_page();page.set_default_timeout(15000)
    page.route(PORTAL+'/d10/callback**',lambda route:route.fulfill(status=200,content_type='text/html',body='<p>Disposable authentication callback</p>'))
    verifier=secrets.token_urlsafe(48);challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    query={'client_id':'zerotrust-spa','redirect_uri':PORTAL+'/d10/callback','response_type':'code','scope':scope,'state':uuid.uuid4().hex,'code_challenge':challenge,'code_challenge_method':'S256'}
    if prompt:query['prompt']=prompt
    if proof:query['claims']=json.dumps({'id_token':{'zt_action_proof':{'value':proof}}})
    if native_action:query['kc_action']=native_action
    page.goto(ISSUER+'/protocol/openid-connect/auth?'+urlencode(query),wait_until='domcontentloaded')
    if page.locator('#username').count():
        require(allow_credentials,'AUTHORIZATION_CODE_MISSING')
        page.locator('#username').fill(actor['username']);page.locator('#password').fill(actor['password']);page.locator('#kc-login').click();page.wait_for_load_state('domcontentloaded')
    used_factor=False;mutation_submitted=False
    if recovery_code is not None:
        if not page.locator('#recoveryCodeInput').count():
            page.locator('#try-another-way').click()
            execution=sql("SELECT e.ID FROM pd_staging_keycloak.AUTHENTICATION_EXECUTION e JOIN pd_staging_keycloak.AUTHENTICATION_FLOW f ON e.FLOW_ID=f.ID JOIN pd_staging_keycloak.REALM r ON f.REALM_ID=r.ID WHERE r.NAME='DoAn' AND e.AUTHENTICATOR='d10-recovery'")[0][0]
            page.locator('li').filter(has=page.locator('[name=authenticationExecution][value="'+execution+'"]')).get_by_role('button').click()
        page.locator('#recoveryCodeInput').fill(recovery_code);page.locator('#kc-login').click();page.wait_for_load_state('domcontentloaded');used_factor=True
        if invalid_recovery:
            require(not parse_qs(urlsplit(page.url).query).get('code') and page.locator('#recoveryCodeInput').count(),'RECOVERY_REPLAY_ACCEPTED');return context,None,None,True
    elif page.locator('input[name=otp]').count():
        if not wrong_otp:
            if actor['id'] not in LAST_FACTOR and int(time.time())//30==START_BUCKET:
                while int(time.time())//30==START_BUCKET:time.sleep(.15)
            while LAST_FACTOR.get(actor['id'])==int(time.time())//30:time.sleep(.15)
            LAST_FACTOR[actor['id']]=int(time.time())//30
        used_factor=True;page.locator('input[name=otp]').fill('not-a-code' if wrong_otp else otp(actor['otp'],LAST_FACTOR[actor['id']]));page.locator('#kc-login').click();page.wait_for_load_state('domcontentloaded')
        for _ in range(2):
            if wrong_otp or not page.locator('input[name=otp]').count():break
            # Native AIA may request another factor. Never replay a time step or skip a challenge.
            # Bounded real submissions also tolerate crossing the period during navigation.
            while int(time.time())//30<=LAST_FACTOR[actor['id']]:time.sleep(.15)
            LAST_FACTOR[actor['id']]=int(time.time())//30
            page.locator('input[name=otp]').fill(otp(actor['otp'],LAST_FACTOR[actor['id']]));page.locator('#kc-login').click();page.wait_for_load_state('domcontentloaded')
    for _ in range(6):
        if enroll and page.locator('input[name=totpSecret]').count():
            actor['otp']=page.locator('input[name=totpSecret]').input_value()
            mutation_submitted=True
            page.locator('input[name=totp]').fill(otp(actor['otp']))
            if page.locator('input[name=userLabel]').count():page.locator('input[name=userLabel]').fill('D10 native isolated')
            page.locator('#kc-submit, #saveTOTPBtn').first.click();LAST_FACTOR[actor['id']]=int(time.time())//30
        elif enroll and page.locator('#kcRecoveryCodesConfirmationCheck').count():
            actor['recovery_codes']=[re.sub(r'^\d+:\s*','',text).strip() for text in page.locator('#kc-recovery-codes-list li').all_text_contents()]
            require(len(actor['recovery_codes'])>=2,'RECOVERY_ENROLLMENT_MISSING');page.locator('#kcRecoveryCodesConfirmationCheck').check();page.locator('#saveRecoveryAuthnCodesBtn').click()
        elif new_password is not None and page.locator('#password-new').count():
            mutation_submitted=True
            page.locator('#password-new').fill(new_password);page.locator('#password-confirm').fill(new_password);page.locator('#kc-submit').click();actor['password']=new_password
        else:break
        page.wait_for_load_state('domcontentloaded')
    code=parse_qs(urlsplit(page.url).query).get('code',[None])[0]
    if wrong_otp:
        require(not code,'OTP_FAILURE_ISSUED_CODE');return context,None,None,used_factor
    if code is None and not exchange and mutation_submitted:
        return context,{'code':None,'verifier':verifier},None,used_factor
    require(code is not None,'AUTHORIZATION_CODE_MISSING_'+('OTP_FORM' if page.locator('input[name=otp]').count() else 'PASSWORD_FORM' if page.locator('#password-new').count() else 'OTHER'))
    if not exchange:return context,{'code':code,'verifier':verifier},None,used_factor
    status,body=exchange_code(code,verifier);require(status==200 and 'access_token'in body,'TOKEN_EXCHANGE_'+str(status));return context,body,claims(body['access_token']),used_factor
def exchange_code(code,verifier):return request(ISSUER+'/protocol/openid-connect/token','POST',{'grant_type':'authorization_code','code':code,'code_verifier':verifier,'redirect_uri':PORTAL+'/d10/callback','client_id':'zerotrust-spa'},form=True)
def revoke(subject,quarantine=False):return authority('revocations',{'subjectId':subject,'operationId':str(uuid.uuid4()),'actorId':'d10-native-fixture','kind':'TEST_REVOCATION','quarantine':quarantine,'disabled':None})
def control(action):
    marker=uuid.uuid4().hex;temp=OUT/'control.tmp';temp.write_text(json.dumps({'id':marker,'action':action}));temp.replace(OUT/'control.json')
    end=time.monotonic()+90
    while time.monotonic()<end:
        f=OUT/'control-ack.json'
        if f.exists() and json.loads(f.read_text()).get('id')==marker:return
        time.sleep(.15)
    raise RuntimeError('CONTROL_TIMEOUT')
def native_user(subject,method='GET',data=None,path=''):
    return request('https://keycloak:8443/admin/realms/DoAn/users/'+subject+path,method,data,service('zerotrust-provisioner'))
def await_status(url,expected=200,timeout=90):
    end=time.monotonic()+timeout;last='unreachable'
    while time.monotonic()<end:
        try:
            last=request(url)[0]
            if last==expected:return
        except Exception:pass
        time.sleep(.5)
    raise RuntimeError('SERVICE_READY_TIMEOUT_'+urlsplit(url).hostname.replace('.','_')+'_'+str(last))
def main():
    global STAGE
    STAGE='readiness';await_status('https://risk:8443/actuator/health');await_status(ISSUER+'/.well-known/openid-configuration')
    await_status('https://backend:8443/api/admin/users',401);await_status(PORTAL+'/api/admin/users',401)
    require(sql("SELECT MAX(CAST(version AS UNSIGNED)) FROM pd_staging_risk.flyway_schema_history WHERE success=1")[0][0]==9,'FIXTURE_V9')
    proxy=start_proxy()
    status,_=request('https://keycloak:8443/admin/realms/DoAn/partialImport','POST',{'ifResourceExists':'FAIL','users':[]},maintenance())
    require(status==403,'UNSUPPORTED_BULK_MUTATION_NOT_BLOCKED')
    fresh_actors();setup_browser()
    with sync_playwright() as playwright:
        browser=playwright.chromium.launch(headless=True,args=['--disable-dev-shm-usage'])
        STAGE='native MFA and RBAC'
        admin_context,admin,admin_claim,factor=authorize(browser,ACTORS['admin']);require(factor,'ADMIN_OTP_NOT_EXECUTED')
        require(admin_claim['exp']-admin_claim['iat']==300,'ACCESS_TTL_DRIFT')
        student_context,student,student_claim,factor=authorize(browser,ACTORS['student_a']);require(factor,'STUDENT_OTP_NOT_EXECUTED')
        second_context,second,second_claim,_=authorize(browser,ACTORS['student_a'])
        other_context,other,other_claim,_=authorize(browser,ACTORS['student_b'])
        for base in (PORTAL,'https://backend:8443'):
            api('/api/admin/users',admin['access_token'],base=base)
            me=api('/api/students/me',student['access_token'],base=base)['data'];scores=api('/api/students/me/scores',student['access_token'],base=base)['data']
            require(me['userId']==sql('SELECT BIN_TO_UUID(id) FROM pd_staging_school.users WHERE keycloak_user_id=UUID_TO_BIN(%s)',(student_claim['sub'],))[0][0],'OWNERSHIP_USER')
            content=scores['content'] if isinstance(scores,dict) else scores
            require(all(score['studentId']==me['id'] for score in content),'SCORE_OWNERSHIP')
            api('/api/admin/users',student['access_token'],403,base);api('/api/admin/users',None,401,base)
        status,_=request('https://risk:8443/internal/v1/security/authorizations','POST',ctx(admin_claim),service('zerotrust-provisioner'));require(status==403,'WRONG_AUTHORITY_CALLER')
        status,_=request('https://risk:8443/internal/v1/security/authorizations','POST',ctx(admin_claim),admin['access_token']);require(status==401,'USER_TOKEN_ACCEPTED_BY_AUTHORITY')
        record('Native ADMIN/STUDENT OTP, signed epoch/SID, Gateway + direct Backend 200/403/401 and ownership')
        STAGE='refresh and SSO'
        status,rotated=refresh(student['refresh_token']);require(status==200,'REFRESH_FAILED');rotated_claim=claims(rotated['access_token']);require(rotated_claim['zt_sec_epoch']==student_claim['zt_sec_epoch'],'REFRESH_EPOCH')
        status,reused=refresh(student['refresh_token']);require(status>=400 and not (isinstance(reused,dict) and 'access_token'in reused),'REFRESH_REUSE_NOT_DENIED')
        _,sso,sso_claim,factor=authorize(browser,ACTORS['student_b'],other_context,prompt=None);require(not factor and sso_claim['sid']==other_claim['sid'],'SSO_REUSE_CONTRACT')
        record('Native refresh rotation/reuse and SSO reuse before revocation')
        _,offline,offline_claim,_=authorize(browser,ACTORS['student_b'],other_context,prompt=None,scope='openid offline_access')
        require(json.loads(base64.urlsafe_b64decode(offline['refresh_token'].split('.')[1]+'==='))['typ']=='Offline','NATIVE_OFFLINE_NOT_ISSUED')
        status,offline_rotated=refresh(offline['refresh_token']);require(status==200,'NATIVE_OFFLINE_REFRESH')
        offline_refresh=offline_rotated.get('refresh_token',offline['refresh_token'])
        record('Native offline token issuance and refresh carry strict epoch/SID binding in isolated optional-scope fixture')
        STAGE='revoke boundaries'
        # An issued code and its authentication ticket predate the authoritative revoke commit.
        _,paused,_,_=authorize(browser,ACTORS['student_a'],exchange=False)
        before_epoch=student_claim['zt_sec_epoch']
        def probe():
            began=time.monotonic();status,_=request('https://backend:8443/api/students/me',token=second['access_token']);return began,status
        with ThreadPoolExecutor(max_workers=8) as pool:
            in_flight=[pool.submit(probe) for _ in range(16)]
            refresh_race=pool.submit(lambda:refresh(second['refresh_token']))
            result=revoke(student_claim['sub']);committed=time.monotonic()
            after=[pool.submit(probe) for _ in range(16)]
            observations=[f.result(timeout=15) for f in in_flight+after]
            require(all(status==401 for began,status in observations if began>=committed),'ALLOW_STARTED_AFTER_COMMIT')
            refresh_status,refresh_body=refresh_race.result(timeout=15)
            if isinstance(refresh_body,dict) and refresh_body.get('access_token'):api('/api/students/me',refresh_body['access_token'],401,'https://backend:8443')
        require(result['epoch']>before_epoch,'EPOCH_NOT_MONOTONIC')
        record('Native concurrent API/refresh/revoke race',{'api_requests':len(observations),'after_commit':sum(began>=committed for began,status in observations),'after_commit_allowed':sum(began>=committed and status==200 for began,status in observations),'refresh_http':refresh_status,'in_flight_rule':'may finish before/after commit; any returned old-epoch JWT denied by new API authorization'})
        for token in (student['access_token'],second['access_token'],rotated['access_token']):
            api('/api/students/me',token,401);api('/api/students/me',token,401,'https://backend:8443')
        for base in (PORTAL,'https://backend:8443'):
            status,_=request(base+'/%61pi/students/me',token=second['access_token']);require(status in (400,401),'ENCODED_API_PREFIX_BYPASSED_AUTHORITY')
        status,body=exchange_code(paused['code'],paused['verifier']);require(status>=400 and not(isinstance(body,dict) and 'access_token'in body),'PAUSED_CODE_ISSUED_AFTER_REVOKE')
        status,body=refresh(second['refresh_token']);require(status>=400 and not(isinstance(body,dict) and 'access_token'in body),'REFRESH_ISSUED_AFTER_REVOKE')
        try:authorize(browser,ACTORS['student_a'],student_context,prompt=None,allow_credentials=False);raise RuntimeError('REVOKED_SSO_ISSUED')
        except RuntimeError as error:require(str(error)=='AUTHORIZATION_CODE_MISSING','SSO_RESULT_UNEXPECTED')
        api('/api/students/me',other['access_token']);api('/api/admin/users',admin['access_token'])
        record('Committed subject revoke denies unexpired JWTs, all subject sessions, paused code, SSO and refresh; other subject unaffected')
        STAGE='fresh proof'
        portal_target=sql('SELECT BIN_TO_UUID(id) FROM pd_staging_school.users WHERE keycloak_user_id=UUID_TO_BIN(%s)',(other_claim['sub'],))[0][0]
        ch=api('/api/admin/users/'+portal_target+'/mfa/reset/challenge',admin['access_token'],method='POST')['data']
        _,_,_,_=authorize(browser,ACTORS['admin'],proof=ch['proofId'],wrong_otp=True)
        require(sql('SELECT state FROM pd_staging_risk.security_action_proofs WHERE proof_id=%s',(ch['proofId'],))[0][0]=='CREATED','FAILED_OTP_PUBLISHED_PROOF')
        action_context,action,action_claim,factor=authorize(browser,ACTORS['admin'],proof=ch['proofId']);require(factor,'ACTION_OTP_NOT_EXECUTED')
        require(action_claim.get('zt_mfa_proof')==ch['proofId'] and action_claim.get('zt_mfa_target')==other_claim['sub'] and action_claim.get('zt_mfa_action')=='MFA_RESET' and action_claim.get('zt_mfa_sid')==action_claim['sid'],'SIGNED_ACTION_PROOF')
        status,action_refresh=refresh(action['refresh_token']);require(status==200,'ACTION_REFRESH');require(claims(action_refresh['access_token'])['zt_mfa_at']==action_claim['zt_mfa_at'],'REFRESH_RESTAMPED_MFA')
        record('Native failed OTP emits no proof; successful OTP emits signed action/target/requester/SID proof; refresh preserves factor time')
        STAGE='durable reset'
        wrong=ACTORS['student_a']['id'];target=other_claim['sub']
        status,body=request('https://risk:8443/internal/v1/security/resets','POST',{'actor':ctx(action_claim),'targetId':wrong,'proofId':ch['proofId'],'operationId':str(uuid.uuid4())},service('zerotrust-portal-security'));require(status==409,'WRONG_TARGET_ACCEPTED')
        # Use Portal's real guard and worker; no direct successful reset fabricated by the harness.
        portal_target=sql('SELECT BIN_TO_UUID(id) FROM pd_staging_school.users WHERE keycloak_user_id=UUID_TO_BIN(%s)',(target,))[0][0]
        FaultProxy.fail_confirmation=True;FaultProxy.fail_effect_response=True;FaultProxy.hold_retry=True
        api('/api/admin/users/'+portal_target+'/mfa/reset',action['access_token'],503,method='POST')
        require(FaultProxy.injected_confirmation and FaultProxy.injected_response,'NATIVE_UNKNOWN_NOT_INJECTED')
        pending=sql("SELECT operation_id,stage,effect_id FROM pd_staging_risk.security_operations WHERE subject_id=%s AND operation_kind='MFA_RESET' ORDER BY created_at DESC LIMIT 1",(target,))[0]
        require(pending[1]=='CREDENTIAL_MUTATION_ACCEPTED','UNKNOWN_NOT_QUARANTINED')
        require(sql("SELECT COUNT(*) FROM pd_staging_keycloak.CREDENTIAL WHERE USER_ID=%s AND TYPE IN ('otp','recovery-authn-codes')",(target,))[0][0]==0,'UNKNOWN_NATIVE_COMMIT_NOT_OBSERVED')
        require(sql('SELECT pending_operation_id FROM pd_staging_risk.security_subjects WHERE subject_id=%s',(target,))[0][0]==pending[0],'PENDING_CLEARED_ON_UNKNOWN')
        control('stop-backend');FaultProxy.released.set();control('start-backend');await_status('https://backend:8443/api/admin/users',401)
        deadline=time.monotonic()+40
        while time.monotonic()<deadline:
            if sql('SELECT stage FROM pd_staging_risk.security_operations WHERE operation_id=%s',(pending[0],))[0][0]=='COMPLETED':break
            time.sleep(.25)
        row=sql("SELECT stage,security_epoch FROM pd_staging_risk.security_operations WHERE subject_id=%s AND operation_kind='MFA_RESET' ORDER BY created_at DESC LIMIT 1",(target,))[0]
        require(row[0]=='COMPLETED','RESET_NOT_DURABLY_COMPLETED')
        require(FaultProxy.admissions[pending[2]]==1,'UNKNOWN_CREDENTIAL_MUTATION_READMITTED')
        require(sql("SELECT COUNT(*) FROM pd_staging_keycloak.CREDENTIAL WHERE USER_ID=%s AND TYPE IN ('otp','recovery-authn-codes')",(target,))[0][0]==0,'MFA_CREDENTIALS_NOT_REMOVED')
        status,body=refresh(offline_refresh);require(status>=400 and not(isinstance(body,dict) and 'access_token'in body),'REVOKED_OFFLINE_ISSUED')
        api('/api/students/me',other['access_token'],401);api('/api/admin/users',action['access_token'])
        # Same proof is idempotent, not a second credential mutation or epoch increment.
        epoch=row[1];api('/api/admin/users/'+portal_target+'/mfa/reset',action['access_token'],204,method='POST')
        require(sql('SELECT security_epoch FROM pd_staging_risk.security_subjects WHERE subject_id=%s',(target,))[0][0]==epoch,'PROOF_REPLAY_INCREMENTED_OR_MUTATED')
        record('Real Portal reset survives native commit + lost confirmation/reply and Portal process restart; committed receipt prevents credential replay; durable completion and proof idempotency',{'credential_admissions':FaultProxy.admissions[pending[2]],'unknown_stage':'CREDENTIAL_MUTATION_ACCEPTED','pending_preserved':True,'backend_restarted':'disposable fixture only'})
        STAGE='native disable and re-enable'
        status,doc=native_user(ACTORS['student_a']['id']);require(status==200,'NATIVE_USER_READ');doc['enabled']=False
        require(native_user(ACTORS['student_a']['id'],'PUT',doc)[0]==204,'NATIVE_DISABLE')
        require(sql('SELECT account_disabled FROM pd_staging_risk.security_subjects WHERE subject_id=%s',(ACTORS['student_a']['id'],))[0][0]==1,'DISABLE_NOT_SYNCHRONIZED')
        doc['enabled']=True;require(native_user(ACTORS['student_a']['id'],'PUT',doc)[0]==204,'NATIVE_ENABLE')
        api('/api/students/me',student['access_token'],401)
        fresh_context,fresh,fresh_claim,_=authorize(browser,ACTORS['student_a']);require(fresh_claim['zt_sec_epoch']>before_epoch,'REENABLE_REVIVED_EPOCH')
        record('Native admin disable/re-enable synchronizes authority; old JWT remains revoked; fresh native MFA can recover')
        STAGE='native password reset'
        new_password=secrets.token_urlsafe(30)
        require(native_user(ACTORS['student_a']['id'],'PUT',{'type':'password','value':new_password,'temporary':False},'/reset-password')[0]==204,'NATIVE_PASSWORD_RESET')
        api('/api/students/me',fresh['access_token'],401)
        ACTORS['student_a']['password']=new_password
        _,current,current_claim,_=authorize(browser,ACTORS['student_a'])
        record('Native admin password reset synchronizes revoke and preserves fresh-login recovery without reviving old JWT')
        STAGE='native self password change'
        old=current;new_password=secrets.token_urlsafe(32)
        _,self_code,_,_=authorize(browser,ACTORS['student_a'],native_action='UPDATE_PASSWORD',new_password=new_password,exchange=False)
        if self_code['code']:
            status,body=exchange_code(self_code['code'],self_code['verifier']);require(status>=400 and not(isinstance(body,dict) and 'access_token'in body),'SELF_PASSWORD_STALE_ATTEMPT_ISSUED')
        api('/api/students/me',old['access_token'],401)
        _,current,current_claim,_=authorize(browser,ACTORS['student_a'])
        record('Native self-service UPDATE_PASSWORD revokes old JWT and pre-mutation ticket; fresh MFA with new password recovers')
        STAGE='self reset and native recovery proof'
        _,admin,admin_claim,_=authorize(browser,ACTORS['admin'])
        admin_portal=ACTORS['admin']['portal_id']
        self_challenge=api('/api/admin/users/'+admin_portal+'/mfa/reset/challenge',admin['access_token'],method='POST')['data']
        _,self_proof,self_claim,_=authorize(browser,ACTORS['admin'],proof=self_challenge['proofId'])
        self_http=reset_wait(admin_portal,ACTORS['admin']['id'],self_proof['access_token'])
        _,enrollment_code,_,_=authorize(browser,ACTORS['admin'],enroll=True,exchange=False)
        if enrollment_code['code']:
            status,body=exchange_code(enrollment_code['code'],enrollment_code['verifier']);require(status>=400 and not(isinstance(body,dict) and 'access_token'in body),'ENROLLMENT_UPGRADED_OLD_TICKET')
        _,admin,admin_claim,_=authorize(browser,ACTORS['admin'])
        require(not admin_claim.get('zt_mfa_proof'),'ORDINARY_OR_ENROLLMENT_INVENTED_ACTION_PROOF')
        recovery_challenge=api('/api/admin/users/'+ACTORS['student_a']['portal_id']+'/mfa/reset/challenge',admin['access_token'],method='POST')['data']
        _,recovery,recovery_claim,_=authorize(browser,ACTORS['admin'],proof=recovery_challenge['proofId'],recovery_code=ACTORS['admin']['recovery_codes'][0])
        require(recovery_claim.get('zt_mfa_method')=='recovery-authn-codes' and recovery_claim.get('zt_mfa_proof')==recovery_challenge['proofId'],'RECOVERY_SIGNED_PROOF')
        authorize(browser,ACTORS['admin'],recovery_code=ACTORS['admin']['recovery_codes'][0],invalid_recovery=True)
        recovery_http=reset_wait(ACTORS['student_a']['portal_id'],ACTORS['student_a']['id'],recovery['access_token'])
        admin=recovery;admin_claim=recovery_claim
        record('Self reset resumes without actor JWT; native enrollment emits no action proof; native recovery -> signed JWT -> real Portal guard succeeds; consumed recovery code rejected',{'self_reset_http':self_http,'recovery_reset_http':recovery_http,'both_operations':'COMPLETED; 503 means visible pending until worker confirmation'})
        STAGE='Redis outage'
        control('stop-redis');api('/api/admin/users',admin['access_token']);revoke(admin_claim['sub']);api('/api/admin/users',admin['access_token'],401);control('start-redis')
        _,admin,admin_claim,_=authorize(browser,ACTORS['admin'])
        record('Redis down/cache loss cannot create a stale allow or revive revoked epoch')
        STAGE='read-only replica refusal'
        control('readonly-mysql')
        try:api('/api/admin/users',admin['access_token'],503);api('/api/admin/users',admin['access_token'],503,'https://backend:8443')
        finally:control('writable-mysql')
        record('Read-only/replica authority cannot return a positive authorization; writer is required')
        STAGE='Risk authority outage'
        control('stop-risk')
        api('/api/admin/users',admin['access_token'],503);api('/api/admin/users',admin['access_token'],503,'https://backend:8443')
        status,body=refresh(admin['refresh_token']);require(status>=400 and not(isinstance(body,dict) and 'access_token'in body),'AUTHORITY_OUTAGE_ISSUED_TOKEN')
        control('start-risk');await_status('https://risk:8443/actuator/health');api('/api/students/me',current['access_token'],401)
        record('Authority outage fails closed at Gateway, Backend and native refresh; restart preserves tombstones')
        STAGE='measurement'
        admin_context,admin,admin_claim,_=authorize(browser,ACTORS['admin'])
        latencies=[]
        for _ in range(40):
            started=time.perf_counter();api('/api/admin/users',admin['access_token']);latencies.append((time.perf_counter()-started)*1000)
        ordered=sorted(latencies)
        record('Measured native strict authorization latency',{'samples':len(ordered),'concurrency':1,'end_to_end_ms':{'p50':round(ordered[len(ordered)//2],2),'p95':round(ordered[int(len(ordered)*.95)-1],2),'max':round(max(ordered),2)},'scope':'isolated TLS ingress + Gateway authority + Backend authority + DB; local single writer; no load extrapolation'})
        started=time.perf_counter()
        with ThreadPoolExecutor(max_workers=4) as pool:
            statuses=list(pool.map(lambda _:request(PORTAL+'/api/admin/users',token=admin['access_token'])[0],range(80)))
        duration=time.perf_counter()-started
        require(all(status in (200,429) for status in statuses),'UNEXPECTED_LOAD_STATUS')
        record('Measured Gateway offered throughput with existing abuse gate',{'requests':80,'concurrency':4,'http_200':statuses.count(200),'http_429':statuses.count(429),'duration_seconds':round(duration,3),'offered_requests_per_second':round(80/duration,2),'scope':'429 is the existing throttle; no security gate disabled'})
        started=time.perf_counter()
        with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(lambda _:api('/api/admin/users',admin['access_token'],base='https://backend:8443'),range(80)))
        duration=time.perf_counter()-started
        record('Measured direct Backend strict authorization throughput',{'requests':80,'concurrency':4,'http_200':80,'duration_seconds':round(duration,3),'requests_per_second':round(80/duration,2),'scope':'protected direct Backend, primary authority on every call; excludes Gateway throttle'})
        STAGE='native logout'
        status,_=request(ISSUER+'/protocol/openid-connect/logout','POST',{'client_id':'zerotrust-spa','refresh_token':admin['refresh_token']},form=True)
        require(status==204,'NATIVE_LOGOUT_STATUS_'+str(status));api('/api/admin/users',admin['access_token'],401,'https://backend:8443')
        end=time.monotonic()+70
        while time.monotonic()<end:
            gateway_status=request(PORTAL+'/api/admin/users',token=admin['access_token'])[0]
            if gateway_status==401:break
            require(gateway_status==429,'LOGOUT_GATEWAY_STATUS_'+str(gateway_status));time.sleep(1)
        require(gateway_status==401,'GATEWAY_THROTTLE_DID_NOT_RECOVER')
        status,body=refresh(admin['refresh_token']);require(status>=400 and not(isinstance(body,dict) and 'access_token'in body),'LOGOUT_REFRESH_ISSUED')
        record('Native logout synchronizes verified SID tombstone and denies unexpired JWT/refresh')
        browser.close()
if __name__=='__main__':
    try:main()
    except Exception as error:
        # Never serialize request objects, browser URLs, headers, tokens, OTP, tracebacks or response bodies.
        safe=str(error) if type(error) is RuntimeError and all(c.isalnum() or c in '_- /' for c in str(error)) else type(error).__name__
        CASES.append({'case':STAGE,'status':'FAIL','reason':safe});save();print('FAIL '+STAGE+' '+safe,flush=True);sys.exit(1)
